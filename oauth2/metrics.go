package oauth2

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

var requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "oauth2",
	Name:      "request_duration_seconds",
	Help:      "Histogram for the number of requests.",
	Buckets:   prometheus.LinearBuckets(0.01, 0.01, 10),
},
	[]string{"endpoint", "status"},
)

func init() {
	prometheus.MustRegister(requestDuration)
}

type httpHandler func(w http.ResponseWriter, r *http.Request)

type statefulWriter struct {
	http.ResponseWriter
	Status int
}

func (w *statefulWriter) WriteHeader(status int) {
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}

func timedHandler(f httpHandler, endpointName string) httpHandler {
	observer := requestDuration.MustCurryWith(prometheus.Labels{"endpoint": endpointName})
	return func(w http.ResponseWriter, r *http.Request) {
		writer := &statefulWriter{ResponseWriter: w}
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			observer.WithLabelValues(fmt.Sprintf("%d", writer.Status)).Observe(v)
		}))
		defer timer.ObserveDuration()
		f(writer, r)
	}
}
