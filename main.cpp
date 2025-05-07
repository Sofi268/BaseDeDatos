#include "BaseDeDatos.h"

int main() {
    BaseDeDatos db;
    //Ejemplo 4
    int userId = 2;
    int requiredLevel = 2;

    if (db.confirmarPermiso(userId, requiredLevel)) {
        std::cout << "Usuario " << userId << " tiene permiso nivel " << requiredLevel << " o superior." << std::endl;
    } else {
        std::cout << "Usuario " << userId << " NO tiene permiso suficiente." << std::endl;
    }

    int warehouseId = 1;
    std::string recurso = "comida";
    int cantidadAgregar = 50;
    int tipoAccionAgregar = 1; // 1 = agregar

    if (db.actualizarInventario(warehouseId, recurso, cantidadAgregar, tipoAccionAgregar)) {
        db.agregarHistorialInventario(warehouseId, recurso, cantidadAgregar, tipoAccionAgregar);
        std::cout << "Inventario actualizado: +" << cantidadAgregar << " " << recurso << std::endl;
    } else {
        std::cout << "Error actualizando inventario (agregar)." << std::endl;
    }

    int cantidadRetirar = 20;
    int tipoAccionRetiro = 2; // 2 = quitar

    if (db.actualizarInventario(warehouseId, recurso, cantidadRetirar, tipoAccionRetiro)) {
        db.agregarHistorialInventario(warehouseId, recurso, cantidadRetirar, tipoAccionRetiro);
        std::cout << "Inventario actualizado: -" << cantidadRetirar << " " << recurso << std::endl;
    } else {
        std::cout << "Error actualizando inventario (retiro)." << std::endl;
    }

    std::string inventarioJson = db.inventario(warehouseId, recurso);
    std::cout << "Inventario actual: " << inventarioJson << std::endl;

    std::string historialJson = db.historialCliente(warehouseId);
    std::cout << "Historial de inventario:\n" << historialJson << std::endl;

    return 0;
}

