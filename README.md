# Station插件
## 插件介绍
### 创建Host
**请求URL：**  `/station/host`

**请求方式：** POST

**请求参数：**

| 参数名      | 类型     | 说明     | 是否必填 |
|:---------|:-------|:-------|:-----|
| hostname | string | Host名称 | 是    |
| ip       | string | ip地址   | 是    |

**请求示例**：

```plain
{
    "hostname": "mine",
    "ip": "192.168.0.103"
}
```
**返回示例：**  

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  更新host
**请求URL：**  `/station/host`

**请求方式：** PUT

#### 请求参数
| 参数名      | 类型     | 说明     | 是否必填 |
|:---------|:-------|:-------|:-----|
| hostname | string | Host名称 | 是    |
| ip       | string | ip地址   | 是    |

**请求示例**：

```plain
{
    "hostname": "mineNew",
    "ip": "192.168.0.103"
}
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  获取host
**请求URL：**  `/station/host`

**请求方式：** GET

#### 请求参数
无

**请求示例**：
无

**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": {
		"HostName": "mineNew",
		"HostID": "0xc529abfdbd95347b9ecd017263916594feb94e65",
		"HostMasterKey": "a81fbcce474917f2bf46dbef797186e26f86a5c8e97a7fb587420b34515faf75",
		"HostIP": "192.168.0.103"
	}
}
```
### 创建Peer
**请求URL：**  `/station/peer`

**请求方式：** POST

**请求参数：**

| 参数名      | 类型     | 说明                | 是否必填 |
|:---------|:-------|:------------------|:-----|
| peerName | string | peer名称            | 是    |
| ip       | string | ip地址              | 是    |
| port     | string | 监听端口号>80, < 60000 | 是    |
| cp       | string | 通信协议              | 是    |
| tp       | string | 传输协议              | 是    |

**请求示例**：

```plain
{
    "peerName": "peerone",
    "ip": "192.168.0.103",
    "port": "11111",
    "cp": "tlv",
    "tp": "tcp"
}
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
### 修改Peer
**请求URL：**  `/station/peer`

**请求方式：** PUT

**请求参数：**

| 参数名      | 类型     | 说明                | 是否必填 |
|:---------|:-------|:------------------|:-----|
| peerId   | string | peer ID           | 是    |
| peerName | string | peer名称            | 是    |
| ip       | string | ip地址              | 是    |
| port     | string | 监听端口号>80, < 60000 | 是    |
| cp       | string | 通信协议              | 是    |
| tp       | string | 传输协议              | 是    |

**请求示例**：

```plain
{
    "peerId": "0xf9b8c0b083b8c226d8c000b8e167c6575691e7e7",
    "peerName": "peeroneNew",
    "ip": "192.168.0.103",
    "port": "11111",
    "cp": "tlv",
    "tp": "tcp"
}
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  删除peer
**请求URL：**  `/station/peer`

**请求方式：** DELETE

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |

**请求示例**：

```plain
/station/peer?peerId=0x1ed114e367fc7
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  获取peer列表
**请求URL：**  `/station/peers`

**请求方式：** GET

#### 请求参数
无

**请求示例**：
无

**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": [
		{
			"PeerName": "peeroneNew",
			"PeerId": "0xf9b8c0b083b8c226d8c000b8e167c6575691e7e7",
			"PeerPubKey": "032e64dcd4251f62371fa9e661fab7068dd58454783e0b9f930d70a17ef3bd8d03",
			"PeerPriKey": "d5fed57a2a00fbde571eedadff8c9fe40db2cd49381e68e0baa93938ee5c5b70",
			"PeerAddr": "192.168.0.103:11111",
			"CommunicationProtocol": "tlv",
			"TransportProtocol": "tcp"
		}
	]
}
```
###  获取peer
**请求URL：**  `/station/peer`

**请求方式：** GET

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |

**请求示例**：
/station/peer?peerId=0xf9115691e7e7

**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": {
		"PeerName": "peeroneNew",
		"PeerId": "0xf9b8c017e7",
		"PeerPubKey": "032e64dc18d03",
		"PeerPriKey": "d5fed57a2a00f1c5b70",
		"PeerAddr": "192.168.0.103:11111",
		"CommunicationProtocol": "tlv",
		"TransportProtocol": "tcp"
	}
}
```
### 启动节点监听
**请求URL：**  `/station/peer/listen`

**请求方式：** POST

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |

**请求示例**：
{
    "peerId": "0x8285d863ee621f875ffde6521151e100c92114f2"
}

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
### 关闭节点监听
**请求URL：**  `/station/peer/listen`

**请求方式：** PUT

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |

**请求示例**：
{
    "peerId": "0x8285d863ee621f875ffde6521151e100c92114f2"
}

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
### 发布信息
**请求URL：**  `/station/peer/message`

**请求方式：** POST

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |
| remotePeerIds | []string | 远程节点，多个用逗号分隔 | 是    |
| message | string | 消息内容 | 是    |

**请求示例**：
{
    "peerId": "0xf9b8c0b083b8c226d8c000b8e167c6575691e7e7",
    "remotePeerIds": "0x8285d863ee621f875ffde6521151e100c92114f2",
    "message": "Hello World"
}

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
### 查看节点消息
**请求URL：**  `/station/peer/messages`

**请求方式：** GET

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | peer id | 是    |
| pageSize | string | 每页条数 | 是    |
| pageNum | string | 页数 | 是    |

**请求示例**：
/station/peer/messages?peerId=0x8285d863ee621f875ffde6521151e100c92114f2&pageSize=10&pageNum=1

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
### 创建RemotePeer
**请求URL：**  `/station/remotePeer`

**请求方式：** POST

**请求参数：**

| 参数名              | 类型     | 说明                | 是否必填 |
|:-----------------|:-------|:------------------|:-----|
| peerId           | string | peer id           | 是    |
| remotePeerName   | string | remote peer名称     | 是    |
| remotePeerId     | string | remote peer id    | 是    |
| remotePeerPubKey | string | remote peer公钥     | 是    |
| ip               | string | ip地址              | 是    |
| port             | string | 监听端口号>80, < 60000 | 是    |
| cp               | string | 通信协议              | 是    |
| tp               | string | 传输协议              | 是    |

**请求示例**：

```plain
{
    "peerId": "0xf9b8c0b0817e7",
    "remotePeerName": "remotePeerOne",
    "remotePeerId": "0x6666c0b017e7",
    "remotePeerPubKey": "022e61d70a17ef3bd8d03",
    "ip": "192.168.0.103",
    "port": "11111",
    "cp": "tlv",
    "tp": "tcp"
}
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
### 修改RemotePeer
**请求URL：**  `/station/remotePeer`

**请求方式：** PUT

**请求参数：**

| 参数名              | 类型     | 说明                | 是否必填 |
|:-----------------|:-------|:------------------|:-----|
| peerId           | string | peer id           | 是    |
| remotePeerName   | string | remote peer名称     | 是    |
| remotePeerId     | string | remote peer id    | 是    |

**请求示例**：

```plain
{
    "peerId": "0xf9b8c0b083b817",
    "remotePeerName": "remotePeerOne",
    "remotePeerId": "0x6666c0b027"
}
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  删除RemotePeer
**请求URL：**  `/station/remotePeer`

**请求方式：** DELETE

#### 请求参数
| 参数名          | 类型     | 说明             | 是否必填 |
|:-------------|:-------|:---------------|:-----|
| peerId       | string | peer id        | 是    |
| remotePeerId | string | remote peer id | 是    |

**请求示例**：

```plain
/station/remotePeer?peerId=0xf911e7&remotePeerId=0x992
```
**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": "success"
}
```
###  获取RemotePeer列表
**请求URL：**  `/station/remotePeers`

**请求方式：** GET

#### 请求参数
| 参数名          | 类型     | 说明             | 是否必填 |
|:-------------|:-------|:---------------|:-----|
| peerId       | string | peer id        | 是    |

**请求示例**：

```plain
/station/remotePeer?peerId=0xf9b123121e7e7
```

**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": [
		{
			"PeerId": "0xf9b8c0b08312e7e7",
			"RemotePeerName": "remotePeerOne",
			"RemotePeerId": "0x6666c0b0812691e7e7",
			"RemotePeerPubKey": "022e64dc120d70a17ef3bd8d03",
			"RemotePeerAddr": "192.168.0.103:11111",
			"RemotePeerSpeed": 0,
			"CommunicationProtocol": "tlv",
			"TransportProtocol": "tcp"
		}
	]
}
```
###  获取RemotePeer
**请求URL：**  `/station/remotePeer`

**请求方式：** GET

#### 请求参数
| 参数名          | 类型     | 说明      | 是否必填 |
|:-------------|:-------|:--------|:-----|
| peerId       | string | peer id | 是    |
| remotePeerId | string | peer id | 是    |

**请求示例**：
/station/remotePeer?peerId=0x12345&remotePeerId=0x23456

**返回示例：**

```plain
{
	"msg": "success",
	"code": 0,
	"data": {
		"PeerId": "0xf9b8c0b08213123123",
		"RemotePeerName": "remotePeerOne",
		"RemotePeerId": "0x6661231231123",
		"RemotePeerPubKey": "021a17ef3bd8d03",
		"RemotePeerAddr": "192.168.0.103:11111",
		"RemotePeerSpeed": 0,
		"CommunicationProtocol": "tlv",
		"TransportProtocol": "tcp"
	}
}
```
### 启动拨号
**请求URL：**  `/station/peer/dial`

**请求方式：** POST

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | 本地节点id | 是    |
| remotePeerId | string | 远程节点id | 是    |

**请求示例**：
{
    "peerId": "0xf9b8c0b083b8c226d8c000b8e167c6575691e7e7",
    "remotePeerId": "0x8285d863ee621f875ffde6521151e100c92114f2"
}

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
### 关闭节点监听
**请求URL：**  `/station/peer/dial`

**请求方式：** PUT

#### 请求参数
| 参数名    | 类型     | 说明      | 是否必填 |
|:-------|:-------|:--------|:-----|
| peerId | string | 本地节点id | 是    |
| remotePeerId | string | 远程节点id | 是    |

**请求示例**：
{
    "peerId": "0xf9b8c0b083b8c226d8c000b8e167c6575691e7e7",
    "remotePeerId": "0x8285d863ee621f875ffde6521151e100c92114f2"
}

**返回示例：**

```plain
{
    "msg": "success",
    "code": 0,
    "data": "success"
}
```
