# Tethys Public Network's Dummy Components with nodejs

- node.js로 만든 grpc 네트워크 에뮬레이터입니다.
- `merger`와 `signer`를 구동시킬 수 있습니다.



## Dummy Merger

### 어떻게 실행하나요?

```npm run meger [port]```

### 무엇을 할 수 있나요?

- `Signer`와 ECDH 키교환
- 연결된 `Signer`에게 `MSG_REQ_SSIG` 전송

### 유의사항

- Self signed certificate을 사용합니다.
- 메세지 검증을 하지는 않습니다.
- 1개의 `Signer`에만 정상적으로 메세지 전송이 가능합니다.
- `MSG_REQ_SSIG` 전송 시, block height는 무의미합니다.



## Dummy Signer

### 어떻게 실행하나요?

```npm run signer [ip_or_address] [port]```

### 무엇을 할 수 있나요?

- `Merger`와  ECDH 키교환
- `MSG_REQ_SSIG`에 대한 지지서명(Aggregate Gamma Signature)을 `MSG_SSIG`로 전송

### 유의사항

- Self signed certificate을 사용합니다.
- 메세지 검증을 하지는 않습니다.
- 1개의 `Merger`에만 접속이 가능합니다.
