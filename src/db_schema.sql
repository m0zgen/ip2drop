create table if not exists ip2drop (
    'ip'        text not NULL primary key,
    'ip_int'    integer,
    'status'    integer,
    'count'     integer,
    'timeout'   integer,
    'date'      TIMESTAMP,
    'group'     text
);