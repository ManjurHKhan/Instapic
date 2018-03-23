from dbconfig import config
import psycopg2


def test_connect():
    """ Connect to the PostgreSQL database server """
    conn = None
    try:
        # read connection parameters
        params = config()
        # connect to the PostgreSQL server
        logger.debug(params)
        conn = psycopg2.connect(**params)
        logger.debug('conn:%s', conn)
        # create a cursor
        cur = conn.cursor()
        
        # Check database version of postgresql
        cur.execute('SELECT version()')
        db_version = cur.fetchone()
        # display the PostgreSQL database server version
        print(db_version)

        # close the communication with the PostgreSQL
        cur.close()
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(params)
        print(error)
        return "TEST CONNECTION FAILED"
    finally:
        if conn is not None:
            conn.close()
            print('Database connection closed.')
            return "Success - CONNECTION  CLOSED..."
        return "CONNECTION NOT CLOSED - conn is nulll :( "
 

if __name__ == "__main__":
    test_connect()