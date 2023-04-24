create table if not exists ip2drop (
    'ip'            text not NULL primary key,
    'ip_int'        integer,
    'status'        integer,
    'count'         integer,
    'timeout'       TIMESTAMP,
    'drop_date'     TIMESTAMP,
    'creation_date' TIMESTAMP,
    'group'         text
);
create table if not exists routines (
    'id'            INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    'last_scan'     TIMESTAMP
);
