package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/goatext/commons-go/errors"
	"github.com/goatext/commons-go/log"
)

const (
	ErrorEmptySqlResult     string = "ERROR_EMPTY_SQL_RESULT"
	ErrorDatabaseDuplicated string = "ERROR_DUPLICATED_ENTRY"
)

type DbPool struct {
	pool *sql.DB
}

// CreateDbPool creates the DB connections pool. time out must be in seconds
func CreateDbPool(user, password, databaseName, host string, port, timeout uint16) (*DbPool, error) {
	var err error

	result := DbPool{}
	dbURI := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&timeout=%ds", user, password, host, port, databaseName, timeout)

	log.Infof("Creating connection to %s:*******@tcp(%s:%d)/%s?parseTime=true&timeout=%ds", user, host, port, databaseName, timeout)

	result.pool, err = sql.Open("mysql", dbURI)
	if err != nil {
		log.Errorf("Failed openning database at {%s}: %+v", dbURI, err)
		return nil, errors.New("ERROR_OPENING_DATABASE", fmt.Sprintf("Failed openning database at {%s}: %+v", dbURI, err))
	}

	if err = result.pool.Ping(); err != nil {
		log.Errorf("Cannot stablish connection with database: %+v", err)
		return nil, errors.New("ERROR_DATABASE_UNREACHABLE", "Cannot stablish connection with database")
	}

	return &result, nil

}

// Gets the DB connection
func (d *DbPool) GetConnection() *sql.DB {
	return d.pool
}

// Close closes de DB connection
func (d *DbPool) Close() {
	if d.pool != nil {
		d.pool.Close()
	}
}

// Returns a new Transaction
func (d *DbPool) BeginTx() (*sql.Tx, error) {

	tx, err := d.pool.BeginTx(context.Background(), nil)
	if err != nil {
		log.Errorf("Error begining transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINING_TRANSACTION", fmt.Sprintf("Error begining transaction: %+v", err))
	}

	return tx, nil

}

// Returns a new Enhaced Improved Transaction
func (d *DbPool) BeginEnhacedTx() (*EnhacedTx, error) {
	tx, err := d.pool.BeginTx(context.Background(), nil)
	if err != nil {
		log.Errorf("Error begining Enhaced transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINING_TRANSACTION", fmt.Sprintf("Error begining Enhaced transaction: %+v", err))
	}

	return &EnhacedTx{tx: tx, open: true}, nil

}

func GetSqlError(err error) error {
	if err == nil {
		return nil
	}

	merror, ok := err.(*mysql.MySQLError)
	if !ok {
		if err.Error() == "sql: no rows in result set" {
			return errors.New(ErrorEmptySqlResult, "Empty sql result")
		}
		return errors.New("ERROR_DATABASE", err.Error())
	}

	if merror.Number == 1062 {
		return errors.New(ErrorDatabaseDuplicated, "Duplicated entity")
	}

	return err

}
