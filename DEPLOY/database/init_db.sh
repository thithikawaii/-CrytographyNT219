HOST_POLICY=${ALLOWED_HOST:-"%"}

echo "=> [DBA] Dang cau hinh phan quyen cho Backend tai Host: $HOST_POLICY"

mysql -u root -p"$MYSQL_ROOT_PASSWORD" <<-EOSQL
    -- 1. Tao user dang nhap tu xa voi quyen han che
    CREATE USER IF NOT EXISTS '$INIT_DB_USER'@'$HOST_POLICY' IDENTIFIED BY '$INIT_DB_PASS';

    -- 2. Cap quyen toi thieu (Least Privilege): Chi SELECT, INSERT, UPDATE. Tuyet doi khong cho DELETE/DROP.
    GRANT SELECT, INSERT, UPDATE ON company_db.* TO '$INIT_DB_USER'@'$HOST_POLICY';

    -- 3. Ap dung thay doi
    FLUSH PRIVILEGES;
EOSQL

echo "=> [DBA] Cau hinh phan quyen Database hoan tat!"