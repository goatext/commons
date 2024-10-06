package interceptor

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/goatext/commons/log"
)

func TimestampHeaderInterceptor() MiddlewareInterceptor {

	return func(w http.ResponseWriter, r *http.Request, chain http.HandlerFunc) {
		if r == nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Errorln(("***ERROR***: Missing Request"))
			return
		}

		if err := checkTimestampHeader(r); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		chain(w, r)
	}
}

func checkTimestampHeader(r *http.Request) error {

	timeStr := r.Header.Get(HEADER_TIMESTAMP)
	tm, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		log.Errorln("Invalid timestamp received")
		return errors.New("invalid timestamp received")
	}
	if time.Now().UnixMilli()-tm > 60*1000 {
		log.Errorln("Invalid timestamp received {%d}", tm)
		return errors.New("invalid timestamp received")
	}

	return nil
}
