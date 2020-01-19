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

// Package index provides indexed data for a HProf file.
package index

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/google/hprof-parser/hprofdata"
	"github.com/google/hprof-parser/parser"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	keyPrefixString          = "string-"
	keyPrefixLoadedClass     = "loadedclass-"
	keyPrefixFrame           = "frame-"
	keyPrefixTrace           = "trace-"
	keyPrefixClass           = "class-"
	keyPrefixInstance        = "instance-"
	keyPrefixObjectArray     = "objectarray-"
	keyPrefixPrimitiveArray  = "primitivearray-"
	keyPrefixRootJNIGlobal   = "rootjniglobal-"
	keyPrefixRootJNILocal    = "rootjnilocal-"
	keyPrefixRootJavaFrame   = "rootjavaframe-"
	keyPrefixRootStickyClass = "rootstickyclass-"
	keyPrefixRootThreadObj   = "rootthreadobj-"
)

// OpenOrCreateIndex opens or creates a DB based on the HProf file.
func OpenOrCreateIndex(heapFilePath, indexFilePath string) (*Index, error) {
	if _, err := os.Stat(indexFilePath); os.IsNotExist(err) {
		if err := createIndex(heapFilePath, indexFilePath); err != nil {
			return nil, err
		}
	}

	db, err := leveldb.OpenFile(indexFilePath, nil)
	if err != nil {
		return nil, err
	}

	return &Index{db: db}, nil
}

func createIndex(heapFilePath, indexFilePath string) error {
	f, err := os.Open(heapFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	db, err := leveldb.OpenFile(indexFilePath, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	p := parser.NewParser(f)
	_, err = p.ParseHeader()
	if err != nil {
		return err
	}

	cs := &counters{}
	var prev int64
	batch := new(leveldb.Batch)
	for {
		r, err := p.ParseRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if pos, err := f.Seek(0, 1); err == nil && pos-prev > (1<<30) {
			log.Printf("currently %d GiB", pos/(1<<30))
			prev = pos
		}

		if err := addRecordToDB(batch, cs, r); err != nil {
			return err
		}
		if batch.Len() > 100000 {
			if err := db.Write(batch, nil); err != nil {
				return err
			}
			batch.Reset()
		}
	}
	return nil
}

type counters struct {
	countJNIGlobal   uint64
	countJNILocal    uint64
	countJavaFrame   uint64
	countStickyClass uint64
	countThreadObj   uint64
}

func addRecordToDB(batch *leveldb.Batch, cs *counters, record interface{}) error {
	var prefix string
	var key uint64
	switch o := record.(type) {
	case *hprofdata.HProfRecordUTF8:
		prefix = keyPrefixString
		key = o.GetNameId()
	case *hprofdata.HProfRecordLoadClass:
		prefix = keyPrefixLoadedClass
		key = uint64(o.GetClassSerialNumber())
	case *hprofdata.HProfRecordFrame:
		prefix = keyPrefixFrame
		key = o.GetStackFrameId()
	case *hprofdata.HProfRecordTrace:
		prefix = keyPrefixTrace
		key = uint64(o.GetStackTraceSerialNumber())
	case *hprofdata.HProfRecordHeapDumpBoundary:
		return nil
	case *hprofdata.HProfClassDump:
		prefix = keyPrefixClass
		key = o.GetClassObjectId()
	case *hprofdata.HProfInstanceDump:
		prefix = keyPrefixInstance
		key = o.GetObjectId()
	case *hprofdata.HProfObjectArrayDump:
		prefix = keyPrefixObjectArray
		key = o.GetArrayObjectId()
	case *hprofdata.HProfPrimitiveArrayDump:
		prefix = keyPrefixPrimitiveArray
		key = o.GetArrayObjectId()
	case *hprofdata.HProfRootJNIGlobal:
		prefix = keyPrefixRootJNIGlobal
		key = cs.countJNIGlobal
		cs.countJNIGlobal++
	case *hprofdata.HProfRootJNILocal:
		prefix = keyPrefixRootJNILocal
		key = cs.countJNILocal
		cs.countJNILocal++
	case *hprofdata.HProfRootJavaFrame:
		prefix = keyPrefixRootJavaFrame
		key = cs.countJavaFrame
		cs.countJavaFrame++
	case *hprofdata.HProfRootStickyClass:
		prefix = keyPrefixRootStickyClass
		key = cs.countStickyClass
		cs.countStickyClass++
	case *hprofdata.HProfRootThreadObj:
		prefix = keyPrefixRootThreadObj
		key = cs.countThreadObj
		cs.countThreadObj++
	default:
		return fmt.Errorf("unknown record type: %#v", record)
	}

	m := record.(proto.Message)
	bs, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	batch.Put(createKey(prefix, key), bs)
	return nil
}

func createKey(prefix string, id uint64) []byte {
	return []byte(prefix + strconv.FormatUint(id, 16))
}

// Index is indexed HProf data.
type Index struct {
	db *leveldb.DB
}

func (idx *Index) loadProto(prefix string, id uint64, m proto.Message) error {
	bs, err := idx.db.Get(createKey(prefix, id), nil)
	if err != nil {
		return err
	}
	return proto.Unmarshal(bs, m)
}

// String returns a name based on a name ID.
func (idx *Index) String(nameID uint64) (string, error) {
	var d hprofdata.HProfRecordUTF8
	if err := idx.loadProto(keyPrefixString, nameID, &d); err != nil {
		return "", err
	}
	return string(d.GetName()), nil
}

// LoadedClass returns a HProfRecordLoadClass based on a class serial number.
func (idx *Index) LoadedClass(classSerialNumber uint32) (*hprofdata.HProfRecordLoadClass, error) {
	var d hprofdata.HProfRecordLoadClass
	if err := idx.loadProto(keyPrefixLoadedClass, uint64(classSerialNumber), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Frame returns a HProfRecordFrame based on a stack frame ID.
func (idx *Index) Frame(stackFrameID uint64) (*hprofdata.HProfRecordFrame, error) {
	var d hprofdata.HProfRecordFrame
	if err := idx.loadProto(keyPrefixFrame, stackFrameID, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Trace returns a HProfRecordTrace based on a stack trace serial number.
func (idx *Index) Trace(stackTraceSerialNumber uint64) (*hprofdata.HProfRecordTrace, error) {
	var d hprofdata.HProfRecordTrace
	if err := idx.loadProto(keyPrefixTrace, stackTraceSerialNumber, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Class returns a HProfClassDump based on a class object ID.
func (idx *Index) Class(classObjectID uint64) (*hprofdata.HProfClassDump, error) {
	var d hprofdata.HProfClassDump
	if err := idx.loadProto(keyPrefixClass, classObjectID, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Instance returns a HProfInstanceDump based on an object ID.
func (idx *Index) Instance(objectID uint64) (*hprofdata.HProfInstanceDump, error) {
	var d hprofdata.HProfInstanceDump
	if err := idx.loadProto(keyPrefixInstance, objectID, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ObjectArray returns a HProfObjectArrayDump based on an array object ID.
func (idx *Index) ObjectArray(arrayObjectID uint64) (*hprofdata.HProfObjectArrayDump, error) {
	var d hprofdata.HProfObjectArrayDump
	if err := idx.loadProto(keyPrefixObjectArray, arrayObjectID, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// PrimitiveArray returns a HProfPrimitiveArrayDump based on an array object ID.
func (idx *Index) PrimitiveArray(arrayObjectID uint64) (*hprofdata.HProfPrimitiveArrayDump, error) {
	var d hprofdata.HProfPrimitiveArrayDump
	if err := idx.loadProto(keyPrefixPrimitiveArray, arrayObjectID, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ForEachRootJNIGlobal iterates through all HProfRootJNIGlobal objects.
func (idx *Index) ForEachRootJNIGlobal(fn func(*hprofdata.HProfRootJNIGlobal) error) error {
	iter := idx.db.NewIterator(util.BytesPrefix([]byte(keyPrefixRootJNIGlobal)), nil)
	defer iter.Release()
	for iter.Next() {
		var d hprofdata.HProfRootJNIGlobal
		if err := proto.Unmarshal(iter.Value(), &d); err != nil {
			return err
		}
		if err := fn(&d); err != nil {
			return err
		}
	}
	return iter.Error()
}

// ForEachRootJNILocal iterates through all HProfRootJNILocal objects.
func (idx *Index) ForEachRootJNILocal(fn func(*hprofdata.HProfRootJNILocal) error) error {
	iter := idx.db.NewIterator(util.BytesPrefix([]byte(keyPrefixRootJNILocal)), nil)
	defer iter.Release()
	for iter.Next() {
		var d hprofdata.HProfRootJNILocal
		if err := proto.Unmarshal(iter.Value(), &d); err != nil {
			return err
		}
		if err := fn(&d); err != nil {
			return err
		}
	}
	return iter.Error()
}

// ForEachRootJavaFrame iterates through all HProfRootJavaFrame objects.
func (idx *Index) ForEachRootJavaFrame(fn func(*hprofdata.HProfRootJavaFrame) error) error {
	iter := idx.db.NewIterator(util.BytesPrefix([]byte(keyPrefixRootJavaFrame)), nil)
	defer iter.Release()
	for iter.Next() {
		var d hprofdata.HProfRootJavaFrame
		if err := proto.Unmarshal(iter.Value(), &d); err != nil {
			return err
		}
		if err := fn(&d); err != nil {
			return err
		}
	}
	return iter.Error()
}

// ForEachRootStickyClass iterates through all HProfRootStickyClass objects.
func (idx *Index) ForEachRootStickyClass(fn func(*hprofdata.HProfRootStickyClass) error) error {
	iter := idx.db.NewIterator(util.BytesPrefix([]byte(keyPrefixRootStickyClass)), nil)
	defer iter.Release()
	for iter.Next() {
		var d hprofdata.HProfRootStickyClass
		if err := proto.Unmarshal(iter.Value(), &d); err != nil {
			return err
		}
		if err := fn(&d); err != nil {
			return err
		}
	}
	return iter.Error()
}

// ForEachRootThreadObj iterates through all HProfRootThreadObj objects.
func (idx *Index) ForEachRootThreadObj(fn func(*hprofdata.HProfRootThreadObj) error) error {
	iter := idx.db.NewIterator(util.BytesPrefix([]byte(keyPrefixRootThreadObj)), nil)
	defer iter.Release()
	for iter.Next() {
		var d hprofdata.HProfRootThreadObj
		if err := proto.Unmarshal(iter.Value(), &d); err != nil {
			return err
		}
		if err := fn(&d); err != nil {
			return err
		}
	}
	return iter.Error()
}
