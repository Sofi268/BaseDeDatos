#include "BaseDeDatos.h"

BaseDeDatos::BaseDeDatos(){
    db = nullptr;
    stmt = nullptr;
    if (!abrirBase("base.db")){
        std::cout<<"Error al abrir la BD"<<std::endl;
        exit(1);
    }
    crearBase();
    llenarBase();
}

BaseDeDatos::~BaseDeDatos() {
    shutDown();
}

bool BaseDeDatos::abrirBase(const std::string& nombre) {
    if (sqlite3_open(nombre.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error abriendo base: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

void BaseDeDatos::shutDown() {
    if (stmt != nullptr) {
        sqlite3_finalize(stmt);
        stmt = nullptr;
    }
    if (db != nullptr) {
        sqlite3_close(db);
        db = nullptr;
    }
}

void BaseDeDatos::resetStmt() {
    if (stmt) {
        sqlite3_finalize(stmt);
        stmt = nullptr;
    }
}

int BaseDeDatos::crearBase() {
    char* errMsg = nullptr;
    const char* tablas[] = {
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "client_type TEXT NOT NULL, "
        "enabled INTEGER NOT NULL DEFAULT 1, "
        "permission_level INTEGER NOT NULL"
        ");",
    
        "CREATE TABLE IF NOT EXISTS warehouse_access ("
        "client_id INTEGER NOT NULL, "
        "warehouse_id INTEGER NOT NULL, "
        "FOREIGN KEY (client_id) REFERENCES users(id), "
        "FOREIGN KEY (warehouse_id) REFERENCES users(id)"
        ");",
    
        "CREATE TABLE IF NOT EXISTS inventory ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "warehouse_id INTEGER NOT NULL, "
        "lastModification TEXT NOT NULL, "
        "resource TEXT NOT NULL, "
        "current_quantity INTEGER NOT NULL, "
        "FOREIGN KEY (warehouse_id) REFERENCES warehouse_access(warehouse_id)"
        ");",

        "CREATE TABLE IF NOT EXISTS action_type ("
        "id INTEGER PRIMARY KEY, "
        "description TEXT NOT NULL"
        ");",
    
        "CREATE TABLE IF NOT EXISTS inventory_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "warehouse_id INTEGER NOT NULL, "
        "date TEXT NOT NULL, "
        "resource TEXT NOT NULL, "
        "quantity INTEGER NOT NULL, "
        "action_type INTEGER NOT NULL, "
        "FOREIGN KEY (warehouse_id) REFERENCES warehouse_access(warehouse_id), "
        "FOREIGN KEY (action_type) REFERENCES action_type(id)"
        ");",
    
        "CREATE TABLE IF NOT EXISTS secret_phrases("
        "id INTEGER PRIMARY KEY, "
        "secret_phrase TEXT NOT NULL,"
        "FOREIGN KEY (id) REFERENCES users(id)"
        ");"
    };
    
    for (const char* sql : tablas) {
        if (!ejecutarSQL(sql, errMsg)) {
            std::cerr << "Error creando tabla: " << errMsg << std::endl;
            sqlite3_free(errMsg);
            shutDown();
            return 1;
        }
    }
    resetStmt();

    return 0;
}

int BaseDeDatos::tieneDatos(const char *tabla) {
    char query[QUERY];
    snprintf(query, sizeof(query), "SELECT 1 FROM %s LIMIT 1;", tabla);

    int tiene = 0;

    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            tiene = 1; 
        }
    }
    resetStmt();
    return tiene;
}

int BaseDeDatos::llenarBase() {
    if (tieneDatos("users") && tieneDatos("action_type") && tieneDatos("secret_phrases")) {
        std::cout << "[INFO] Las tablas ya tienen datos. No se insertó nada.\n";
        return 0;
    }

    if (!tieneDatos("usuarios") && !insertarUsuarios()) {
        std::cerr << "[ERROR] Falló la inserción de usuarios.\n";
        return 1;
    }

    if (!tieneDatos("acciones") && !insertarAcciones()) {
        std::cerr << "[ERROR] Falló la inserción de acciones.\n";
        return 1;
    }

    if (!tieneDatos("frases_secretas") && !insertarFrasesSecretas()) {
        std::cerr << "[ERROR] Falló la inserción de frases secretas.\n";
        return 1;
    }

    return 0;
}

bool BaseDeDatos::ejecutarSQL(const char* sql, char*& errMsg) {
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
    return rc == SQLITE_OK;
}

bool BaseDeDatos::insertarUsuarios() {
    const char* sql_insert = "INSERT OR IGNORE INTO users (username, password_hash, client_type, enabled, permission_level) VALUES (?, ?, ?, 1, ?);";

    std::vector<User> users = {
        {"juan", "password123", "h", 1},
        {"maria", "1234", "w", 2},
        {"admin", "adminpass", "h", 7}
    };

    return prepararEInsertar(sql_insert, users);
}

bool BaseDeDatos::insertarAcciones() {
    const char* sql_action = "INSERT OR IGNORE INTO action_type (id, description) VALUES (?, ?);";

    std::vector<Action> actions = {
        {1, "ADD"},
        {2, "REMOVE"},
        {3, "TRANSFER"},
        {4, "ADJUST"},
        {5, "CHECK"}
    };

    return prepararEInsertar(sql_action, actions);
}

bool BaseDeDatos::insertarFrasesSecretas() {
    const char* sql = "INSERT OR IGNORE INTO secret_phrases (id, secret_phrase) VALUES (?, ?);";

    std::vector<FraseSecreta> frases = {
        {1, "el sol cae al oeste"},
        {2, "agua y fuego son uno"},
        {3, "la luna es testigo"}
    };

    return prepararEInsertar(sql, frases);
}

template <typename T> bool BaseDeDatos::prepararEInsertar(const char* sql, const std::vector<T>& data) {
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Error preparing insert: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    for (const auto& item : data) {
        if (!insertarDatos(item)) {
            return false;
        }
        sqlite3_reset(stmt);
    }
    resetStmt();
    return true;
}

bool BaseDeDatos::insertarDatos(const User& user) {
    int rc = sqlite3_bind_text(stmt, 1, user.name.c_str(), -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 2, hashPassword(user.password).c_str(), -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 3, user.clientType.c_str(), -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_int(stmt, 4, user.permissionLevel);

    if (rc != SQLITE_OK) {
        std::cerr << "Error binding user values: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    rc = sqlite3_step(stmt);
    return rc == SQLITE_DONE;
}

bool BaseDeDatos::insertarDatos(const Action& action) {
    int rc = sqlite3_bind_int(stmt, 1, action.id);
    rc |= sqlite3_bind_text(stmt, 2, action.description.c_str(), -1, SQLITE_TRANSIENT);

    if (rc != SQLITE_OK) {
        std::cerr << "Error binding action values: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    rc = sqlite3_step(stmt);
    return rc == SQLITE_DONE;
}

bool BaseDeDatos::insertarDatos(const FraseSecreta& sp) {
    int rc = sqlite3_bind_int(stmt, 1, sp.id);
    rc |= sqlite3_bind_text(stmt, 2, sp.secret_phrase.c_str(), -1, SQLITE_TRANSIENT);

    if (rc != SQLITE_OK) {
        std::cerr << "Error binding secret_phrase values: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    rc = sqlite3_step(stmt);
    return rc == SQLITE_DONE;
}

bool BaseDeDatos::comprobarUsuario(const std::string& usuario, const std::string& contrasenia, bool& existe, bool& habilitado) {
    existe = false;
    habilitado = false;

    const char* sql = "SELECT password_hash, enabled FROM users WHERE username = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparando SELECT.\n";
        return false;
    }

    sqlite3_bind_text(stmt, 1, usuario.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        return false;
    }

    existe = true;
    habilitado = sqlite3_column_int(stmt, 1);
    std::string hashAlmacenado(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    std::string hashIngresado = hashPassword(contrasenia);

    return hashAlmacenado == hashIngresado;
}

bool BaseDeDatos::autenticarUsuario() {
    std::string usuario;
    std::cout << "Ingrese su nombre de usuario: ";
    std::getline(std::cin, usuario);

    int intentos = 3;
    while (intentos-- > 0) {
        std::string contrasenia;
        std::cout << "Ingrese su contraseña: ";
        std::getline(std::cin, contrasenia);

        bool existe = false, habilitado = false;
        bool loginOk = comprobarUsuario(usuario, contrasenia, existe, habilitado);

        if (!existe) {
            std::cerr << "El usuario no existe.\n";
            return false;  // Retorna false si el usuario no existe.
        }

        if (!habilitado) {
            std::cerr << "El usuario está bloqueado.\n";
            return false;  // Retorna false si el usuario está bloqueado.
        }

        if (loginOk) {
            std::cout << "¡Login exitoso!\n";
            return true;  // Retorna true si el login es exitoso.
        }

        if (intentos > 0)
            std::cerr << "Contraseña incorrecta. Intentos restantes: " << intentos << "\n";
    }

    std::cerr << "Demasiados intentos fallidos. Bloqueando usuario...\n";
    bloquearUsuario(usuario);
    return false;  // Retorna false si se excedieron los intentos fallidos.
}

std::string BaseDeDatos::hashPassword(const std::string& password) {
    std::hash<std::string> hasher;
    size_t hashed = hasher(password);
    return std::to_string(hashed);
}

void BaseDeDatos::bloquearUsuario(const std::string& usuario) {
    const char* sql = "UPDATE users SET enabled = 0 WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparando UPDATE: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    if (sqlite3_bind_text(stmt, 1, usuario.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "Error vinculando usuario para bloqueo: " << sqlite3_errmsg(db) << std::endl;
        resetStmt();
        return;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Error ejecutando UPDATE: " << sqlite3_errmsg(db) << std::endl;
    } else {
        std::cout << "Usuario bloqueado correctamente.\n";
    }

    resetStmt();
}

bool BaseDeDatos::desbloqueo(int id) {
    const char *sql = "SELECT secret_phrase FROM secret_phrases WHERE id = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error al preparar statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        std::cerr << "Error al bindear ID: " << sqlite3_errmsg(db) << std::endl;
        resetStmt();
        return false;
    }

    std::string fraseAlmacenada;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text) {
            fraseAlmacenada = reinterpret_cast<const char*>(text);
        }
    } else {
        std::cerr << "ID no encontrado o error al ejecutar: " << sqlite3_errmsg(db) << std::endl;
        resetStmt();
        return false;
    }

    resetStmt();

    std::string fraseIngresada;
    std::cout << "Ingrese su frase secreta: ";
    std::getline(std::cin, fraseIngresada);

    if (fraseIngresada == fraseAlmacenada) {
        std::cout << "Frase correcta. Usuario desbloqueado.\n";
        desbloquearUsuario(id);  
        return true;
    } else {
        std::cerr << "Frase incorrecta. Usuario sigue bloqueado.\n";
        return false;
    }
}

void BaseDeDatos::desbloquearUsuario(int id) {
    const char* sql = "UPDATE users SET enabled = 1 WHERE id = ?;";
    if (prepararSQL(sql, std::to_string(id))) {
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error ejecutando desbloqueo.\n";
        }
    }
}

bool BaseDeDatos::prepararSQL(const char* sql, const std::string& parametro) {
    resetStmt();
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparando sentencia SQL: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, parametro.c_str(), -1, SQLITE_STATIC);
    return true;
}

bool BaseDeDatos::confirmarPermiso(int id, int level) {
    const char* sql = "SELECT permission_level FROM users WHERE id = ?;"; 
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Error al preparar consulta de permisos: " << sqlite3_errmsg(db) << std::endl;
        return false; 
    }

    // Enlazamos el id al primer parámetro de la consulta
    rc = sqlite3_bind_int(stmt, 1, id);
    if (rc != SQLITE_OK) {
        std::cerr << "Error al vincular el ID: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);  // Finalizamos el statement antes de salir
        return false;
    }

    // Ejecutamos la consulta
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int permisoAlmacenado = sqlite3_column_int(stmt, 0);  // Asumimos que el nivel de permiso es un entero
        sqlite3_finalize(stmt);

        // Comparamos el nivel de permiso del usuario con el solicitado
        return permisoAlmacenado >= level;  // Si el nivel de permisos almacenado es mayor o igual al solicitado, devolvemos true
    } else {
        std::cerr << "Usuario no encontrado o error en la consulta: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;  // No se encontró el usuario o hubo un error en la consulta
    }
}

bool BaseDeDatos::agregarHistorialInventario(int warehouseId, std::string recurso, int cantidad, int accionType) {

    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    std::string fecha = oss.str();

    const char* sql = "INSERT INTO inventory_history (warehouse_id, date, resource, quantity, action_type) VALUES (?, ?, ?, ?, ?);";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Error preparando insert en historial: " << sqlite3_errmsg(db) << std::endl;
        shutDown();
        return false;
    }

    sqlite3_bind_int(stmt, 1, warehouseId);
    sqlite3_bind_text(stmt, 2, fecha.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, recurso.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, cantidad);
    sqlite3_bind_int(stmt, 5, accionType);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Error insertando en historial: " << sqlite3_errmsg(db) << std::endl;
        resetStmt();
        return false;
    }

    resetStmt();
    return true;
}

bool BaseDeDatos::actualizarInventario(int warehouseId, std::string recurso, int cantidad, int accionType) {

    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    std::string fecha = oss.str();

    // Verifica si ya existe ese recurso en ese warehouse
    const char* selectSQL = "SELECT id, current_quantity FROM inventory WHERE warehouse_id = ? AND resource = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Error preparando select: " << sqlite3_errmsg(db) << std::endl;
        shutDown();
        return false;
    }

    sqlite3_bind_int(stmt, 1, warehouseId);
    sqlite3_bind_text(stmt, 2, recurso.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW);
    int idInventario = exists ? sqlite3_column_int(stmt, 0) : -1;
    int cantidadActual = exists ? sqlite3_column_int(stmt, 1) : 0;
    sqlite3_finalize(stmt);

    if (exists) {

        int nuevaCantidad = cantidadActual;
        if (accionType == 1) {
            nuevaCantidad += cantidad;
        } else if (accionType == 2) {
            if (cantidadActual < cantidad) {
                return false;
            }
            nuevaCantidad -= cantidad;
            faltaStock(nuevaCantidad, recurso);
        } else {
            return false;
        }

            const char* updateSQL = "UPDATE inventory SET current_quantity = ?, lastModification = ? WHERE id = ?;";
            rc = sqlite3_prepare_v2(db, updateSQL, -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                std::cerr << "Error preparando update: " << sqlite3_errmsg(db) << std::endl;
                shutDown();
                return false;
            }

            sqlite3_bind_int(stmt, 1, nuevaCantidad);
            sqlite3_bind_text(stmt, 2, fecha.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, idInventario);
    } else {
        // No existe el recurso, solo se puede insertar si se está agregando
        if (accionType != 1) {
            shutDown();
            return false; // No se puede retirar lo que no existe
        }

        const char* insertSQL = "INSERT INTO inventory (warehouse_id, lastModification, resource, current_quantity) VALUES (?, ?, ?, ?);";
        rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "Error preparando insert: " << sqlite3_errmsg(db) << std::endl;
            shutDown();
            return false;
        }

        sqlite3_bind_int(stmt, 1, warehouseId);
        sqlite3_bind_text(stmt, 2, fecha.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, recurso.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, cantidad);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Error ejecutando modificación de inventario: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        shutDown();
        return false;
    }

    resetStmt();
    return true;
}

void BaseDeDatos::faltaStock(int cantActual, std::string recurso) {
    int minimo = 0;

    if (recurso == "comida") {
        minimo = MIN_COMIDA;
        if(cantActual < minimo){
            faltaComida = true;
        }
    } else if (recurso == "agua") {
        minimo = MIN_AGUA;
        if(cantActual < minimo){
            faltaAgua = true;
        }
    } else if (recurso == "medicina") {
        minimo = MIN_MEDICINA;
        if(cantActual < minimo){
            faltaMedicina = true;
        }
    } else if (recurso == "municion") {
        minimo = MIN_MUNICION;
        if(cantActual < minimo){
            faltaMuniciones = true;
        }
    } else {
        std::cerr << "Recurso desconocido: " << recurso << std::endl;
        return;
    }
}

std::string BaseDeDatos::historialCliente(int idCliente) {

    const char* sql = "SELECT date, resource, quantity, description "
                      "FROM inventory_history "
                      "JOIN action_type ON inventory_history.action_type = action_type.id "
                      "WHERE warehouse_id = ? "
                      "ORDER BY date ASC;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparando SELECT: " << sqlite3_errmsg(db) << std::endl;
        shutDown();
        return "[]";
    }

    sqlite3_bind_int(stmt, 1, idCliente);

    std::ostringstream json;
    json << "[";

    bool first = true;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) json << ",";
        first = false;

        std::string fecha = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string recurso = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int cantidad = sqlite3_column_int(stmt, 2);
        std::string accion = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        json << "{"
             << "\"fecha\":\"" << fecha << "\","
             << "\"recurso\":\"" << recurso << "\","
             << "\"cantidad\":" << cantidad << ","
             << "\"accion\":\"" << accion << "\""
             << "}";
    }

    json << "]";
    resetStmt();
    return json.str();
}

std::string BaseDeDatos::inventario(int idCliente, const std::string& recurso) {

    const char* sql = "SELECT resource, current_quantity, lastModification "
                      "FROM inventory WHERE warehouse_id = ? AND resource = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparando SELECT: " << sqlite3_errmsg(db) << std::endl;
        shutDown();
        return "{}";
    }

    sqlite3_bind_int(stmt, 1, idCliente);
    sqlite3_bind_text(stmt, 2, recurso.c_str(), -1, SQLITE_TRANSIENT);

    std::ostringstream json;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string res = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        int cantidad = sqlite3_column_int(stmt, 1);
        std::string fecha = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

        json << "{"
             << "\"recurso\":\"" << res << "\","
             << "\"cantidad\":" << cantidad << ","
             << "\"ultimaModificacion\":\"" << fecha << "\""
             << "}";
    } else {
        json << "{}";
    }
    resetStmt();
    return json.str();
}

