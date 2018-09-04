#!/usr/bin/python
"""
Simple database utility tool, support basic 'insert', 'delete','select','update'
and support basic filter in SQL with '+' and '|' operation
"""
import MySQLdb

__all__ = ['set_db_debug', 'db_debug', 'show_db_debug', 'Filter', 'Mydb']

_db_debug = False

def set_db_debug(flag=False):
    global _db_debug
    _db_debug = flag

def _print(message):
    global _db_debug
    if _db_debug == True:
        print message

def db_debug(message, *args):
    _print(message % args)


def show_db_debug():
    global _db_debug
    print _db_debug

class Filter(object):
    """
    filter in SQLs
    """
    ##currently support these operations
    _operation = ('=', '<=', '>=', 'like', 'in')

    @staticmethod
    def make_str():
        return ' where ' + self.str
        
    def __init__(self, *obj):
        self.str = ""
        if obj and isinstance(obj[0],list):
            self._gen_str(obj[0])
        elif obj:
            self._gen_str([obj])

    def __add__(self, obj):
        """
        overload '+' represent 'and' in MySQL 
        """
        assert(isinstance(obj, Filter))
        tmp = Filter()
        tmp.str = ' and '.join([self.str, obj.get_str()])
        return tmp

    def __or__(self, obj):
        """
        overload '|' operation which represent 'or' in MySQL
        """
        assert(isinstance(obj, Filter))
        tmp = Filter()
        tmp.str = ' or '.join(['(' + self.str, obj.get_str() + ')'])
        return tmp
        
    def get_str(self):
        """
        return filter string
        """
        return self.str
    
    def _gen_str(self, filter_list):
        """
        given filter list, generate full filter string when Filter(args) is called
        """
        self.str = ' and '.join(self._process(filter_list))

    def _process(self, filter_list):
        """
        given filter list, generate filter string item, one by one
        """
        for f, o, v in filter_list:
            if isinstance(v, str) and o.lower() != 'in':
                item = f + o + "'%s'"%v
            elif o.lower() == 'in':
                if not isinstance(v,(list,tuple)):
                    v = list(v)
                assert(v)
                if isinstance(v[0], str):
                    item = f + ' ' + o + '(' + ','.join("'%s'"%i for i in v) + ')'
                else:
                    item = f + ' ' + o + '(' + ','.join('%s'%i for i in v) + ')'
            else:
                item = f + o + "%s"%v
            yield item



class Mydb(object):
    def __init__(self, db_name, user_name, passwd):
        self.db = MySQLdb.connect(host='localhost', user=user_name, passwd=passwd, db=db_name, charset='utf8')
        self.cursor=self.db.cursor()

    def insert(self, table_name=None, repeat=1, **attr):
        """
        insert record to database, you can specify any fields by keywords,
        default insert only 1 records
        """
        assert(attr and table_name != None)
        SQL_FMT = "insert into %s(%s) values(%s);"
        keys = attr.keys()
        values = attr.values()
        cols = ','.join(i for i,j in zip(keys,values) if j != None)
        vals = ','.join(Mydb.process_value(i) for i in values if i != None)
        SQL = SQL_FMT%(table_name,cols,vals)
        db_debug(SQL)
        for i in xrange(repeat):
            self.cursor.execute(SQL)
        self.db.commit()

    #filter is a list of (field, operation, data)
    def delete(self, table_name=None, filter=None):
        """
        delete record from database
        """
        assert(table_name != None)        
        SQL_FMT = "delete from %s "
        SQL = SQL_FMT % table_name
        if filter:
            SQL = SQL + "where " + filter.get_str()
        db_debug(SQL)
        self.cursor.execute(SQL)
        self.db.commit()

    def update(self, table_name=None, filter=None, **attr):
        """
        update record from database
        **attr** is a dictionary,the keys correspond to the column
                 the value is the value users going to set for the column
        **filter** is a list of (column,operation,value) represent filters
                 in 'where' clause
        """
        assert(table_name != None and attr)
        attr_setting = ",".join(Mydb.process_value2(attr))
        
        SQL_FMT = "update %s set "
        SQL = SQL_FMT % table_name + attr_setting

        if filter:
            SQL = SQL + " where " + filter.get_str()
        db_debug(SQL)
        self.cursor.execute(SQL)
        self.db.commit()
    
    def select(self, table_name=None, attr=None, filter=None):
        """
        select record in database
        """
        assert(table_name != None)
        SQL_FMT = "select %s from %s "
        if not attr:
            SQL = SQL_FMT % ('*', table_name)
        else:
            SQL = SQL_FMT % (','.join(attr), table_name)
        if filter:
            SQL = SQL + " where " + filter.get_str()
        db_debug(SQL)
        self.cursor.execute(SQL)
        rows=self.cursor.fetchall()
        return rows

    def close(self):
        """
        close database connection
        """
        self.db.close()

    @staticmethod    
    def process_value(val):
        """
        prepare data for sql insert statement,
        given a value, convert it to string,
        if the value is string type add a pair of ''
        """
        if val == None:
            return ''
        if isinstance(val,str):
            return "'%s'"%str(val)
        else:
            return str(val)

    @staticmethod
    def process_value2(attr):
        """
        attr is a dict with key:value
        generate strings like "key=value"
        """
        for key in attr:
            if isinstance(attr[key], str):
                item = key + "=" +"'%s'"%attr[key]
            else:
                item = key + "=" + "%s"%attr[key]
            yield item



if __name__ == '__main__':
    db = Mydb(db_name='risk_mgmt_db', user_name='root', passwd='hillstone')
    ##select
    rows = db.select(table_name='threat_event_tbl',attr=['event_name','is_ioc']
    , filter=Filter('defender_id','=',5))
    print len(rows)
    rows = db.select(table_name='threat_event_tbl',attr=['event_name','is_ioc']
    , filter=Filter('defender_id','=',5) + (Filter('event_name', 'in', ['http','smb']) |
    Filter('is_ioc','=',0)) + Filter('confidence','>',50))
    print len(rows)
    rows = db.select(table_name='threat_event_tbl'
    ,filter=Filter([('defender_id','=',5),('confidence','>', 50)]))
    print len(rows)
    ##update
    db.update(table_name='threat_event_tbl',priv_data='python-db-update'
    , filter=Filter('confidence','=',100) + Filter('is_ioc','=', 1))
    ##delete
    db.delete(table_name='threat_event_tbl'
    , filter=Filter('confidence','>',0)|Filter('need_show','=',1))
    db.delete('threat_event_tbl')
    ##insert
    db.insert(table_name='threat_event_tbl', repeat=1, is_ioc=1,confidence=100
    , event_name='python-db-insert', src_ip=None)

    db.close()
