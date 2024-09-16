package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type Account struct {
	Address     string
	Balance     uint
	BlockNumber uint64
}

func hashData(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

type MPTNode struct {
	Key   []byte
	Value []byte
	Left  *MPTNode
	Right *MPTNode
}

// 插入账户到 MPT 树
func insertAccount(root *MPTNode, account Account) *MPTNode {
	data := []byte(fmt.Sprintf("%s:%d:%d", account.Address, account.Balance, account.BlockNumber))
	hash := hashData(data)
	if root == nil {
		return &MPTNode{Key: hash, Value: data}
	}
	// 比较哈希值进行插入
	cmp := bytes.Compare(hash, root.Key)
	if cmp < 0 {
		root.Left = insertAccount(root.Left, account)
	} else if cmp > 0 {
		root.Right = insertAccount(root.Right, account)
	} else {
		root.Value = data
	}
	return root
}

// 在指定区块中查找账户余额
func findAccountBalanceInBlock(root *MPTNode, address string, blockNumber uint64) uint {
	hash := hashData([]byte(fmt.Sprintf("%s:%d", address, blockNumber)))
	current := root
	for current != nil {
		cmp := bytes.Compare(hash, current.Key)
		if cmp == 0 {
			data := current.Value
			// 解析数据获取余额
			parts := bytes.Split(data, []byte(":"))
			if len(parts) == 3 {
				balance, _ := binary.Uvarint(parts[1])
				return balance
			}
			return 0
		} else if cmp < 0 {
			current = current.Left
		} else {
			current = current.Right
		}
	}
	return 0
}

func main() {
	root := nil
	account1 := Account{Address: "0x123", Balance: 100, BlockNumber: 5}
	account2 := Account{Address: "0x456", Balance: 200, BlockNumber: 5}
	root = insertAccount(root, account1)
	root = insertAccount(root, account2)

	address := "0x123"
	blockNumber := uint64(5)
	balance := findAccountBalanceInBlock(root, address, blockNumber)
	fmt.Printf("在区块 %d 中，账户 %s 的余额: %d\n", blockNumber, address, balance)
}
