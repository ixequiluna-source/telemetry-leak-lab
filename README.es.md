![telemetry-leak-lab](assets/cover.svg)

# telemetry-leak-lab

**Eliminar el texto visible no garantiza que desaparezca el identificador.**

Laboratorio de Python que compara exportaciones JSON antes y después de un filtro. Busca valores sintéticos conocidos y sus variantes; también exige que la información de control siga disponible. Un hash conocido puede seguir identificando el mismo registro.

[English y referencia completa](README.md) · [Diseño](docs/DESIGN.md) · [Informe de ejemplo](docs/example-report.html)

```sh
python -m telemetry_leak_lab demo --out artifacts
```

Abre `artifacts/report.html`. El experimento ejecuta tres situaciones: fuga restante (**LEAK**), canarios eliminados con controles conservados (**PASS**) y telemetría útil perdida (**INCONCLUSIVE**).

Para tus exportaciones sintéticas, usa `compare` con `--before`, `--after`, `--manifest` y `--out`. Consulta `examples/`. Códigos de salida: 0 aprobado, 1 fuga, 2 inconcluso o entrada inválida. Python 3.11 o superior; sin dependencias de ejecución ni conexión de red.

El alcance son canarios conocidos en JSON, no toda la información personal posible. No valida cumplimiento normativo, no implementa un Collector y no demuestra que una exportación real carezca de datos sensibles. Las ubicaciones del informe son ordinales para no volver a publicar una clave que contenga el dato buscado.

Autor: **Dr. Ixequi Luna**. Licencia MIT con atribución.
