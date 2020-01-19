// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package parser provides OpenJDK's hprof heap dump parser.
//
// Parse hprof binary dump format as described in
// http://hg.openjdk.java.net/jdk/jdk/file/4b49cfba69fe/src/hotspot/share/services/heapDumper.cpp.
package parser

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/hprof-parser/hprofdata"
)

// HProfRecordType is a HProf record type.
type HProfRecordType byte

// HProfHDRecordType is a HProf heap dump subrecord type.
type HProfHDRecordType byte

// HProf's record types.
const (
	HProfRecordTypeUTF8            HProfRecordType = 0x01
	HProfRecordTypeLoadClass                       = 0x02
	HProfRecordTypeUnloadClass                     = 0x03
	HProfRecordTypeFrame                           = 0x04
	HProfRecordTypeTrace                           = 0x05
	HProfRecordTypeAllocSites                      = 0x06
	HProfRecordTypeHeapSummary                     = 0x07
	HProfRecordTypeStartThread                     = 0x0a
	HProfRecordTypeEndThread                       = 0x0b
	HProfRecordTypeHeapDump                        = 0x0c
	HProfRecordTypeHeapDumpSegment                 = 0x1c
	HProfRecordTypeHeapDumpEnd                     = 0x2c
	HProfRecordTypeCPUSamples                      = 0x0d
	HProfRecordTypeControlSettings                 = 0x0e

	HProfHDRecordTypeRootUnknown     HProfHDRecordType = 0xff
	HProfHDRecordTypeRootJNIGlobal                     = 0x01
	HProfHDRecordTypeRootJNILocal                      = 0x02
	HProfHDRecordTypeRootJavaFrame                     = 0x03
	HProfHDRecordTypeRootNativeStack                   = 0x04
	HProfHDRecordTypeRootStickyClass                   = 0x05
	HProfHDRecordTypeRootThreadBlock                   = 0x06
	HProfHDRecordTypeRootMonitorUsed                   = 0x07
	HProfHDRecordTypeRootThreadObj                     = 0x08

	HProfHDRecordTypeClassDump          HProfHDRecordType = 0x20
	HProfHDRecordTypeInstanceDump                         = 0x21
	HProfHDRecordTypeObjectArrayDump                      = 0x22
	HProfHDRecordTypePrimitiveArrayDump                   = 0x23
)

var (
	// ValueSize is a size of the HProf values.
	ValueSize = map[hprofdata.HProfValueType]int{
		hprofdata.HProfValueType_OBJECT:  -1,
		hprofdata.HProfValueType_BOOLEAN: 1,
		hprofdata.HProfValueType_CHAR:    2,
		hprofdata.HProfValueType_FLOAT:   4,
		hprofdata.HProfValueType_DOUBLE:  8,
		hprofdata.HProfValueType_BYTE:    1,
		hprofdata.HProfValueType_SHORT:   2,
		hprofdata.HProfValueType_INT:     4,
		hprofdata.HProfValueType_LONG:    8,
	}
)

// HProfHeader is a HProf file header.
type HProfHeader struct {
	// Magic string.
	Header string
	// The size of object IDs.
	IdentifierSize uint32
	// Dump creation time.
	Timestamp time.Time
}

// HProfParser is a HProf file parser.
type HProfParser struct {
	reader                 *bufio.Reader
	identifierSize         int
	heapDumpFrameLeftBytes uint32
}

// NewParser creates a new HProf parser.
func NewParser(r io.Reader) *HProfParser {
	return &HProfParser{
		reader: bufio.NewReader(r),
	}
}

// ParseHeader parses the HProf header.
func (p *HProfParser) ParseHeader() (*HProfHeader, error) {
	bs, err := p.reader.ReadSlice(0x00)
	if err != nil {
		return nil, err
	}

	is, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	p.identifierSize = int(is)

	tsHigh, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	tsLow, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	var tsMilli int64 = int64(tsHigh)
	tsMilli <<= 32
	tsMilli += int64(tsLow)

	return &HProfHeader{
		Header:         string(bs),
		IdentifierSize: is,
		Timestamp:      time.Unix(0, 0).Add(time.Duration(tsMilli * int64(time.Millisecond))),
	}, nil
}

// ParseRecord returns the next HProf record.
//
// HProf file consists of sequence of records. Heapdump records and heapdump
// segement records contains subrecords inside. This method parses out those
// recordss and subrecords and returns one record for each. The returned value
// is one of the followings:
//
// *   `*hprofdata.HProfRecordUTF8`
// *   `*hprofdata.HProfRecordLoadClass`
// *   `*hprofdata.HProfRecordFrame`
// *   `*hprofdata.HProfRecordTrace`
// *   `*hprofdata.HProfRecordHeapDumpBoundary`
// *   `*hprofdata.HProfClassDump`
// *   `*hprofdata.HProfInstanceDump`
// *   `*hprofdata.HProfObjectArrayDump`
// *   `*hprofdata.HProfPrimitiveArrayDump`
// *   `*hprofdata.HProfRootJNIGlobal`
// *   `*hprofdata.HProfRootJNILocal`
// *   `*hprofdata.HProfRootJavaFrame`
// *   `*hprofdata.HProfRootStickyClass`
// *   `*hprofdata.HProfRootThreadObj`
//
// It returns io.EOF at the end of the file.
func (p *HProfParser) ParseRecord() (interface{}, error) {
	if p.heapDumpFrameLeftBytes > 0 {
		return p.parseHeapDumpFrame()
	}

	rt, err := p.reader.ReadByte()
	if err != nil {
		return nil, err
	}

	_, err = p.readUint32()
	if err != nil {
		return nil, err
	}

	sz, err := p.readUint32()
	if err != nil {
		return nil, err
	}

	switch HProfRecordType(rt) {
	case HProfRecordTypeUTF8:
		nameID, err := p.readID()
		if err != nil {
			return nil, err
		}
		bs := make([]byte, int(sz)-p.identifierSize)
		if _, err := io.ReadFull(p.reader, bs); err != nil {
			return nil, err
		}
		return &hprofdata.HProfRecordUTF8{
			NameId: nameID,
			Name:   bs,
		}, nil
	case HProfRecordTypeLoadClass:
		csn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		tsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		cnid, err := p.readID()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRecordLoadClass{
			ClassSerialNumber:      csn,
			ClassObjectId:          oid,
			StackTraceSerialNumber: tsn,
			ClassNameId:            cnid,
		}, nil
	case HProfRecordTypeFrame:
		sfid, err := p.readID()
		if err != nil {
			return nil, err
		}
		mnid, err := p.readID()
		if err != nil {
			return nil, err
		}
		msgnid, err := p.readID()
		if err != nil {
			return nil, err
		}
		sfnid, err := p.readID()
		if err != nil {
			return nil, err
		}
		csn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		ln, err := p.readInt32()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRecordFrame{
			StackFrameId:      sfid,
			MethodNameId:      mnid,
			MethodSignatureId: msgnid,
			SourceFileNameId:  sfnid,
			ClassSerialNumber: csn,
			LineNumber:        ln,
		}, nil
	case HProfRecordTypeTrace:
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		tsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		nr, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		sfids := []uint64{}
		for i := uint32(0); i < nr; i++ {
			sfid, err := p.readID()
			if err != nil {
				return nil, err
			}
			sfids = append(sfids, sfid)
		}
		return &hprofdata.HProfRecordTrace{
			StackTraceSerialNumber: stsn,
			ThreadSerialNumber:     tsn,
			StackFrameIds:          sfids,
		}, nil
	case HProfRecordTypeHeapDumpSegment:
		if sz == 0 {
			// Truncated. Set to the max int.
			sz = math.MaxUint32
		}
		p.heapDumpFrameLeftBytes = sz
		return &hprofdata.HProfRecordHeapDumpBoundary{}, nil
	case HProfRecordTypeHeapDumpEnd:
		return &hprofdata.HProfRecordHeapDumpBoundary{}, nil
	default:
		return nil, fmt.Errorf("unknown record type: 0x%x", rt)
	}
}

func (p *HProfParser) parseHeapDumpFrame() (interface{}, error) {
	rt, err := p.readByte()
	if err != nil {
		return nil, err
	}

	switch HProfHDRecordType(rt) {
	case HProfHDRecordTypeRootJNIGlobal:
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		rid, err := p.readID()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRootJNIGlobal{
			ObjectId:       oid,
			JniGlobalRefId: rid,
		}, nil

	case HProfHDRecordTypeRootJNILocal:
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		tsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		fn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRootJNILocal{
			ObjectId:                oid,
			ThreadSerialNumber:      tsn,
			FrameNumberInStackTrace: fn,
		}, nil

	case HProfHDRecordTypeRootJavaFrame:
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		tsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		fn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRootJavaFrame{
			ObjectId:                oid,
			ThreadSerialNumber:      tsn,
			FrameNumberInStackTrace: fn,
		}, nil

	case HProfHDRecordTypeRootStickyClass:
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRootStickyClass{
			ObjectId: oid,
		}, nil

	case HProfHDRecordTypeRootThreadObj:
		toid, err := p.readID()
		if err != nil {
			return nil, err
		}
		tsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfRootThreadObj{
			ThreadObjectId:           toid,
			ThreadSequenceNumber:     tsn,
			StackTraceSequenceNumber: stsn,
		}, nil

	case HProfHDRecordTypeClassDump:
		coid, err := p.readID()
		if err != nil {
			return nil, err
		}
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		scoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		cloid, err := p.readID()
		if err != nil {
			return nil, err
		}
		sgnoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		pdoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		_, err = p.readID()
		if err != nil {
			return nil, err
		}
		_, err = p.readID()
		if err != nil {
			return nil, err
		}
		insz, err := p.readUint32()
		if err != nil {
			return nil, err
		}

		cpsz, err := p.readUint16()
		if err != nil {
			return nil, err
		}
		cps := []*hprofdata.HProfClassDump_ConstantPoolEntry{}
		for i := uint16(0); i < cpsz; i++ {
			ty, err := p.readByte()
			if err != nil {
				return nil, err
			}
			v, err := p.readValue(hprofdata.HProfValueType(ty))
			if err != nil {
				return nil, err
			}
			cps = append(cps, &hprofdata.HProfClassDump_ConstantPoolEntry{
				Type:  hprofdata.HProfValueType(ty),
				Value: v,
			})
		}

		sfsz, err := p.readUint16()
		if err != nil {
			return nil, err
		}
		sfs := []*hprofdata.HProfClassDump_StaticField{}
		for i := uint16(0); i < sfsz; i++ {
			sfnid, err := p.readID()
			if err != nil {
				return nil, err
			}
			ty, err := p.readByte()
			if err != nil {
				return nil, err
			}
			v, err := p.readValue(hprofdata.HProfValueType(ty))
			if err != nil {
				return nil, err
			}
			sfs = append(sfs, &hprofdata.HProfClassDump_StaticField{
				NameId: sfnid,
				Type:   hprofdata.HProfValueType(ty),
				Value:  v,
			})
		}

		ifsz, err := p.readUint16()
		if err != nil {
			return nil, err
		}
		ifs := []*hprofdata.HProfClassDump_InstanceField{}
		for i := uint16(0); i < ifsz; i++ {
			ifnid, err := p.readID()
			if err != nil {
				return nil, err
			}
			ty, err := p.readByte()
			if err != nil {
				return nil, err
			}
			ifs = append(ifs, &hprofdata.HProfClassDump_InstanceField{
				NameId: ifnid,
				Type:   hprofdata.HProfValueType(ty),
			})
		}

		return &hprofdata.HProfClassDump{
			ClassObjectId:            coid,
			StackTraceSerialNumber:   stsn,
			SuperClassObjectId:       scoid,
			ClassLoaderObjectId:      cloid,
			SignersObjectId:          sgnoid,
			ProtectionDomainObjectId: pdoid,
			InstanceSize:             insz,
			ConstantPoolEntries:      cps,
			StaticFields:             sfs,
			InstanceFields:           ifs,
		}, nil

	case HProfHDRecordTypeInstanceDump:
		oid, err := p.readID()
		if err != nil {
			return nil, err
		}
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		coid, err := p.readID()
		if err != nil {
			return nil, err
		}
		fsz, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		bs, err := p.readBytes(int(fsz))
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfInstanceDump{
			ObjectId:               oid,
			StackTraceSerialNumber: stsn,
			ClassObjectId:          coid,
			Values:                 bs,
		}, nil

	case HProfHDRecordTypeObjectArrayDump:
		aoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		asz, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		acoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		vs := []uint64{}
		for i := uint32(0); i < asz; i++ {
			v, err := p.readID()
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
		return &hprofdata.HProfObjectArrayDump{
			ArrayObjectId:          aoid,
			StackTraceSerialNumber: stsn,
			ArrayClassObjectId:     acoid,
			ElementObjectIds:       vs,
		}, nil

	case HProfHDRecordTypePrimitiveArrayDump:
		aoid, err := p.readID()
		if err != nil {
			return nil, err
		}
		stsn, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		asz, err := p.readUint32()
		if err != nil {
			return nil, err
		}
		ty, err := p.readByte()
		if err != nil {
			return nil, err
		}
		bs, err := p.readArray(hprofdata.HProfValueType(ty), int(asz))
		if err != nil {
			return nil, err
		}
		return &hprofdata.HProfPrimitiveArrayDump{
			ArrayObjectId:          aoid,
			StackTraceSerialNumber: stsn,
			ElementType:            hprofdata.HProfValueType(ty),
			Values:                 bs,
		}, nil
	default:
		return nil, fmt.Errorf("unknown heap dump record type: 0x%x", rt)
	}
}

func (p *HProfParser) readByte() (byte, error) {
	b, err := p.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes--
	}
	return b, nil
}

func (p *HProfParser) readID() (uint64, error) {
	var v uint64
	if p.identifierSize == 8 {
		if err := binary.Read(p.reader, binary.BigEndian, &v); err != nil {
			return 0, err
		}
	} else if p.identifierSize == 4 {
		var v2 uint32
		if err := binary.Read(p.reader, binary.BigEndian, &v2); err != nil {
			return 0, err
		}
		v = uint64(v2)
	} else {
		return 0, fmt.Errorf("odd identifier size: %d", p.identifierSize)
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= uint32(p.identifierSize)
	}
	return v, nil
}

func (p *HProfParser) readBytes(n int) ([]byte, error) {
	bs := make([]byte, n)
	if _, err := io.ReadFull(p.reader, bs); err != nil {
		return nil, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= uint32(len(bs))
	}
	return bs, nil
}

func (p *HProfParser) readArray(ty hprofdata.HProfValueType, n int) ([]byte, error) {
	sz := ValueSize[ty]
	if sz == -1 {
		sz = p.identifierSize
	}
	if sz == 0 {
		return nil, fmt.Errorf("odd value type: %d", ty)
	}

	bs := make([]byte, int(sz)*n)
	if _, err := io.ReadFull(p.reader, bs); err != nil {
		return nil, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= uint32(len(bs))
	}
	return bs, nil
}

func (p *HProfParser) readValue(ty hprofdata.HProfValueType) (uint64, error) {
	sz := ValueSize[ty]
	if sz == -1 {
		sz = p.identifierSize
	}
	if sz == 0 {
		return 0, fmt.Errorf("odd value type: %d", ty)
	}

	bs := make([]byte, 8)
	if _, err := io.ReadFull(p.reader, bs[:int(sz)]); err != nil {
		return 0, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= uint32(sz)
	}
	return binary.BigEndian.Uint64(bs), nil
}

func (p *HProfParser) readUint16() (uint16, error) {
	var v uint16
	if err := binary.Read(p.reader, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= 2
	}
	return v, nil
}

func (p *HProfParser) readUint32() (uint32, error) {
	var v uint32
	if err := binary.Read(p.reader, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= 4
	}
	return v, nil
}

func (p *HProfParser) readInt32() (int32, error) {
	var v int32
	if err := binary.Read(p.reader, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	if p.heapDumpFrameLeftBytes > 0 {
		p.heapDumpFrameLeftBytes -= 4
	}
	return v, nil
}
