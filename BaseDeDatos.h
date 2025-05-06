#include <iostream>
#include <string.h>
#include <cstring>
#include <sqlite3.h>
#include <functional>  
#include <unistd.h> 
#include <ctime>
#include <iomanip>
#include <sstream>

#define QUERY 256
#define MIN_AGUA 5
#define MIN_COMIDA 10
#define MIN_MEDICINA 15
#define MIN_MUNICION 5


class BaseDeDatos {
    public:
        BaseDeDatos();
        ~BaseDeDatos();
        bool autenticarUsuario();
        void bloquearUsuario(const std::string& usuario);
        bool confirmarPermiso(int id, int level);
        bool desbloqueo(int id);
        bool agregarHistorialInventario(int idWarehouse, std::string recurso, int cantidad, int accionType);
        bool actualizarInventario(int idWarehouse, std::string recurso, int cantidad, int accionType);
        std::string historialCliente(int idCliente); 
        std::string inventario(int idCliente, const std::string& recurso); 

    private:
        sqlite3* db = nullptr;
        sqlite3_stmt* stmt = nullptr;
        bool faltaAgua;
        bool faltaComida;
        bool faltaMedicina;
        bool faltaMuniciones;

        struct User {
            std::string name;
            std::string password;
            std::string clientType;
            int permissionLevel;
        };

        struct Action {
            int id;
            std::string description;
        };

        struct InventoryEntry {
            int idInventory = 0; 
            int warehouseId;
            std::string date; 
            std::string resource;
            int quantity;
            int actionType;
        };

        struct FraseSecreta {
            int id;
            std::string secret_phrase;
        };

        bool abrirBase(const std::string& nombre);
        void shutDown();
        void resetStmt();
        bool comprobarUsuario(const std::string& usuario, const std::string& contrasenia, bool& existe, bool& habilitado);
        std::string hashPassword(const std::string& password);
        int crearBase();
        int llenarBase();
        void faltaStock(int cantActual, std::string recurso);
        template <typename T> bool prepararEInsertar(const char* sql, const std::vector<T>& data);
        bool insertarFrasesSecretas();
        bool insertarAcciones();
        bool insertarUsuarios();
        bool ejecutarSQL(const char* sql, char*& errMsg);
        bool prepararSQL(const char* sql, const std::string& parametro);
        bool insertarDatos(const FraseSecreta& sp);
        bool insertarDatos(const Action& action);
        bool insertarDatos(const User& user);
        void desbloquearUsuario(int id);
        int tieneDatos(const char *tabla);

};
