module github.com/kfsoftware/hlf-cc-dev

go 1.16

require (
	github.com/99designs/gqlgen v0.14.0
	github.com/go-sql-driver/mysql v1.5.1-0.20200311113236-681ffa848bae // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gosimple/slug v1.12.0
	github.com/hashicorp/yamux v0.0.0-20211028200310-0bc27b27de87
	github.com/hyperledger/fabric-config v0.1.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20201028172056-a3136dde2354
	github.com/hyperledger/fabric-sdk-go v1.0.0
	github.com/kfsoftware/getout v0.0.4-beta2
	github.com/lib/pq v1.10.2
	github.com/lithammer/shortuuid/v3 v3.0.7
	github.com/mattn/go-sqlite3 v1.14.8 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/shurcooL/graphql v0.0.0-20200928012149-18c5c3165e3a
	github.com/sirupsen/logrus v1.8.1
	github.com/slok/go-http-metrics v0.9.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.0
	github.com/vektah/gqlparser/v2 v2.2.0
	golang.org/x/crypto v0.0.0-20210920023735-84f357641f63 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	k8s.io/client-go v0.23.1
)

replace github.com/go-kit/kit => github.com/go-kit/kit v0.8.0

replace github.com/kfsoftware/getout => github.com/kfsoftware/getout v0.0.4-beta2
