package vring

import (
	"errors"
	"fmt"
)

var ErrVRingSizeInvalid = errors.New("vring size is invalid")

func CheckVRingSize(vringSize int) error {
	if vringSize <= 0 {
		return fmt.Errorf("%w: %d is too small",
			ErrVRingSizeInvalid, vringSize)
	}

	if vringSize&(vringSize-1) != 0 {
		return fmt.Errorf("%w: %d is not a power of 2",
			ErrVRingSizeInvalid, vringSize)
	}

	if vringSize > 32768 {
		return fmt.Errorf("%w: %d is larger than the max vring size 32768",
			ErrVRingSizeInvalid, vringSize)
	}

	return nil
}
