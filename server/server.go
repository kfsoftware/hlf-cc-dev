package server

import (
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/apollotracing"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	clientmsp "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-cc-dev/gql"
	"github.com/kfsoftware/hlf-cc-dev/gql/resolvers"
	"github.com/kfsoftware/hlf-cc-dev/log"
	"github.com/kfsoftware/hlf-cc-dev/server/metrics"
	"github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	middlewarestd "github.com/slok/go-http-metrics/middleware/std"
	"io"
	"net/http"
	"time"
)

type MetricsRegistry interface {
	IncGraphqlRequest(statusCode int)
	ObserveGraphqlMutation(duration time.Duration)
}

type BlockchainServerOpts struct {
	Address        string
	MetricsAddress string
	SDK            *fabsdk.FabricSDK
	SDKContext     context.ClientProvider
	SDKContextMap  map[string]context.ClientProvider
	GWClient       *client.Gateway

	Channel       string
	MSPClient     *clientmsp.Client
	CAConfig      *msp.CAConfig
	Organization  string
	User          string
	ConfigBackend core.ConfigProvider
}

type BlockchainAPIServer struct {
	BlockchainServerOpts
	metrics MetricsRegistry
	stopCh  chan struct{}
}

func NewServer(opts BlockchainServerOpts) *BlockchainAPIServer {
	return &BlockchainAPIServer{
		BlockchainServerOpts: opts,
	}
}

func (a *BlockchainAPIServer) Run() {
	metricsServ := metrics.NewMetricsServer(a.MetricsAddress)
	mux := a.setupHttpServer()
	go func() {
		log.Infof("Server listening on %s", a.Address)
		a.checkServeErr("server", http.ListenAndServe(a.Address, mux))
	}()
	go func() {
		log.Infof("Metrics server listening on %s", a.MetricsAddress)
		a.checkServeErr("metrics", metricsServ.ListenAndServe())
	}()
	a.stopCh = make(chan struct{})
	<-a.stopCh
}

func (a *BlockchainAPIServer) setupHttpServer() http.Handler {
	serverMux := http.NewServeMux()
	config := gql.Config{
		Resolvers: &resolvers.Resolver{
			SDK:           a.SDK,
			SDKContext:    a.SDKContext,
			Channel:       a.Channel,
			MSPClient:     a.MSPClient,
			CAConfig:      a.CAConfig,
			SDKContextMap: a.SDKContextMap,
			Organization:  a.Organization,
			ConfigBackend: a.ConfigBackend,
			User:          a.User,
			GWClient:      a.GWClient,
		},
	}
	es := gql.NewExecutableSchema(config)
	h := handler.New(es)
	h.AddTransport(transport.Options{})
	h.AddTransport(transport.GET{})
	h.AddTransport(transport.POST{})
	h.AddTransport(transport.MultipartForm{})

	h.SetQueryCache(lru.New(1000))
	h.Use(extension.Introspection{})
	h.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New(100),
	})
	h.Use(apollotracing.Tracer{})
	metrics.Register()
	h.Use(metrics.Tracer{})
	//
	//jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
	//	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
	//		iss := a.Issuer
	//		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
	//		if !checkIss {
	//			return token, errors.New("Invalid issuer.")
	//		}
	//
	//		cert, err := getPemCert(token, a.JWKSUrl)
	//		if err != nil {
	//			panic(err.Error())
	//		}
	//		return cert, nil
	//	},
	//	SigningMethod:       jwt.SigningMethodRS256,
	//	CredentialsOptional: true,
	//})

	graphqlHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Identity")
		writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		h.ServeHTTP(writer, request)
	})
	serverMux.HandleFunc(
		"/graphql",
		graphqlHandler,
	)
	playgroundHandler := playground.Handler("GraphQL", "/graphql")
	serverMux.HandleFunc(
		"/playground",
		playgroundHandler,
	)
	serverMux.HandleFunc(
		"/healthz",
		func(w http.ResponseWriter, request *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"alive": true}`)
		},
	)

	mdlw := middleware.New(middleware.Config{
		Recorder: prometheus.NewRecorder(prometheus.Config{}),
	})
	httpHandler := middlewarestd.Handler("", mdlw, serverMux)
	return httpHandler
}

// checkServeErr checks the error from a .Serve() call to decide if it was a graceful shutdown
func (a *BlockchainAPIServer) checkServeErr(name string, err error) {
	if err != nil {
		if a.stopCh == nil {
			// a nil stopCh indicates a graceful shutdown
			log.Infof("graceful shutdown %s: %v", name, err)
		} else {
			log.Fatalf("%s: %v", name, err)
		}
	} else {
		log.Infof("graceful shutdown %s", name)
	}
}
