package cryptokit

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sort"
)

type BlindIndex struct {
	Version int
	Value   []byte
}

type BlindIndexer struct {
	current int
	keys    map[int][]byte
}

func NewBlindIndexer(current int, keys map[int][]byte) (*BlindIndexer, error) {
	if _, ok := keys[current]; !ok {
		return nil, errors.New("current blind-index version has no key")
	}
	cloned := make(map[int][]byte, len(keys))
	for version, key := range keys {
		if version < 1 || len(key) < 32 {
			return nil, errors.New("invalid blind-index key")
		}
		cloned[version] = append([]byte(nil), key...)
	}
	return &BlindIndexer{current: current, keys: cloned}, nil
}

func (b *BlindIndexer) Current(message []byte) BlindIndex {
	return BlindIndex{Version: b.current, Value: digest(b.keys[b.current], message)}
}

func (b *BlindIndexer) All(message []byte) []BlindIndex {
	versions := make([]int, 0, len(b.keys))
	for version := range b.keys {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	result := make([]BlindIndex, 0, len(versions))
	for _, version := range versions {
		result = append(result, BlindIndex{Version: version, Value: digest(b.keys[version], message)})
	}
	return result
}

func digest(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(message)
	return h.Sum(nil)
}
