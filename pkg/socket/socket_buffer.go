package socket

const (
	MAX_WND_SIZE = 65535
)

type CircularBuffer struct {

    // Circular Buffer used for SENDing and RECEIVing bytes

	// The Buffer
	Buffer []byte
	// Pointer to next write position
	NextWrite int
    // Pointer to next get position
    NextRead int
}

func InitCircularBuffer() *CircularBuffer {
	return &CircularBuffer{
		NextWrite: 0,
		Buffer:    make([]byte, MAX_WND_SIZE),
	}
}

func InitTestCircularBuffer() *CircularBuffer {
	return &CircularBuffer{
		NextWrite: 0,
		Buffer:    make([]byte, 10),
	}
}

// Function that put data into Buffer
// Assumption is that the caller of this function is ready to send "data"
func (cb *CircularBuffer) Put(data []byte) {
	to_put := len(data)
	idx := 0
	// While there is data to put
	for to_put > 0 {
		remain := cb.PutRemain()
		// Two cases:
		// 1. Can put everything
		// 2. Wraps around

		// Case 1:
		// Example: Put "he"
		//        p                  p
		// - [* * + + +] -> [* * h e +]
		// - Remain = 3, to_put = 2, NextWrite = 2
		// - cb.Buffer[2:4]
		if remain >= to_put {
			start := cb.NextWrite
			end := start + to_put
			b := copy(cb.Buffer[start:end], data[idx:])
			cb.NextWrite += b
			if cb.NextWrite == len(cb.Buffer) {
				// Wrap around
				cb.NextWrite = 0
			}
			return
		}

		// Case 2:
		// Example: Put "he"
		//            p      p
		// - [* * * * +] -> [e * * * h]
		// - Remain = 1, to_put = 2, NextWrite = 4
		start := cb.NextWrite
		end := cb.NextWrite + remain
		b := copy(cb.Buffer[start:end], data[idx:idx+remain])
		idx += b
		cb.NextWrite = 0
		to_put -= b
	}
}

// Function that extracts the data out of the buffer.
// Assumption is that the caller of this function is ready to read "data"
func (cb *CircularBuffer) Get(buf []byte) {
	to_get := len(buf)
    idx := 0
    // While there is data to get
    for to_get > 0 {
        remain := cb.GetRemain()
        // Two cases 
        // - Can get all at once
        // - Wraps around

        // Case 1:     p
        // Example 1: [h e l l o]
        // Remain =  5, to_get = 4, NextRead = 0
        //                 p         
        // Example 2: [h e l l o]
        // Remain =  3, to_get = 3, NextRead = 2
        if remain >= to_get {
            start := cb.NextRead
            end := cb.NextRead + to_get
            b := copy(buf[idx:], cb.Buffer[start:end])
            cb.NextRead += b
            if cb.NextRead == len(cb.Buffer) {
                // Wraps around
                cb.NextRead = 0
            }
            return
        }

        // Case 2:           p
        // Example 1: [h e l l o]
        // Remain = 2, to_get = 3, NextRead = 3
        start := cb.NextRead
        end := cb.NextRead + remain
        b := copy(buf[idx:], cb.Buffer[start:end])
        idx += b
        cb.NextRead = 0
        to_get -= b
    }
}

// Get the number of bytes we can "PUT" until we reach the end
// Example:
// Buffer Size is 10 so valid index [0, 9]
// - NextWrite = 5
// cb.Remain() = 5 -> We can write at indices 5, 6, 7, 8, and 9
func (cb *CircularBuffer) PutRemain() int {
	return len(cb.Buffer) - int(cb.NextWrite)
}

// Get the number of bytes we can "GET" until we reach the end
// Example:
// Buffer Size is 10 so valid index [0, 9]
// - NextRead = 5
// cb.Remain() = 5 -> We can get bytes at indices 5, 6, 7, 8, and 9
func (cb *CircularBuffer) GetRemain() int {
    return len(cb.Buffer) - int(cb.NextRead)
}