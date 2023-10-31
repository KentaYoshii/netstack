package socket

import (
    "testing"
)

var s1 = "test1"
var s2 = "test2"
var s3 = "1234"

func TestSimplePut(t *testing.T) {
    // Init a test buffer of size 10
    cb := InitTestCircularBuffer()
    cb.Put([]byte(s1)) // test1
    if cb.NextWrite != 5 {
        t.Fatalf("Put error, want cb.NextWrite %d, received %d", 5, cb.NextWrite)
    }
    str := string(cb.Buffer[0:5])
    if str != s1 {
        t.Fatalf("Put error, want string %s, received %s", s1, str)
    }
    if cb.PutRemain() != 5 {
        t.Fatalf("Put error, want remain %d, received %d", 5, cb.PutRemain())
    }
    cb.Put([]byte(s2)) // test2
    if cb.NextWrite != 0 {
        // Wraps around
        t.Fatalf("Put error, want cb.NextWrite %d, received %d", 0, cb.NextWrite)
    }
    if cb.PutRemain() != 10 {
        t.Fatalf("Put error, want remain %d, received %d", 10, cb.PutRemain())
    }
    str = string(cb.Buffer[5:10])
    if str != s2 {
        t.Fatalf("Put error, want string %s, received %s", s2, str)
    }
}

func TestPutWrapAround(t *testing.T) {
    // Init a test buffer of size 10
    cb := InitTestCircularBuffer()
    cb.Put([]byte(s1)) // test1
    cb.Put([]byte(s3)) // 1234
    if cb.PutRemain() != 1 {
        t.Fatalf("Put error, want remain %d, received %d", 1, cb.PutRemain())
    }
    if cb.NextWrite != 9 {
        t.Fatalf("Put error, want cb.NextWrite %d, received %d", 9, cb.NextWrite)
    }
    //[ test11234 * ]
    // Test wrap around behavior
    cb.Put([]byte(s2)) // test2 -> [ est211234t ]
    if cb.NextWrite != 4 {
        t.Fatalf("Put error, want cb.NextWrite %d, received %d", 4, cb.NextWrite)
    }
    if cb.PutRemain() != 6 {
        t.Fatalf("Put error, want remain %d, received %d", 6, cb.PutRemain())
    }
    str := string(cb.Buffer)
    if str != "est211234t" {
        t.Fatalf("Put error, want string %s, received %s", "est211234t", str)
    }
}

func TestSimpleGet(t *testing.T) {
    // Init a test buffer of size 10
    cb := InitTestCircularBuffer()
    cb.Put([]byte(s1))
    cb.Put([]byte(s2))
    // [t e s t 1 t e s t 2]
    buf := make([]byte, 5)
    // Get 5 bytes
    cb.Get(buf)
    if cb.GetRemain() != 5 {
        t.Fatalf("Get error, want remain %d, received %d", 5, cb.GetRemain())
    }
    str := string(buf)
    if str != s1 {
        t.Fatalf("Get error, want string %s, received %s", s1, str)
    }
    // Get 5 bytes
    // - NextRead wraps around
    cb.Get(buf)
    if cb.GetRemain() != 10 {
        t.Fatalf("Get error, want remain %d, received %d", 10, cb.GetRemain())
    }
    str = string(buf)
    if str != s2 {
        t.Fatalf("Get error, want string %s, received %s", s2, str)
    }
}

func TestGetWrapAround(t *testing.T) {
    // Init a test buffer of size 10
    cb := InitTestCircularBuffer()
    cb.Put([]byte(s1)) // test1
    cb.Put([]byte(s2)) // test2
    cb.Put([]byte(s3)) // 1234
    //[ 1 2 3 4 1 t e s t 2 ]
    // Test wrap around behavior
    buf := make([]byte, 6)
    // Get 6 bytes
    cb.Get(buf)
    if cb.GetRemain() != 4 {
        t.Fatalf("Get error, want remain %d, received %d", 4, cb.GetRemain())
    }
    str := string(buf)
    if str != "12341t" {
        t.Fatalf("Get error, want string %s, received %s", "12341t", str)
    }
    // Get 6 bytes
    cb.Get(buf)
    if cb.GetRemain() != 8 {
        t.Fatalf("Get error, want remain %d, received %d", 8, cb.GetRemain())
    }
    str = string(buf)
    if str != "est212" {
        t.Fatalf("Get error, want string %s, received %s", "est212", str)
    }
}
