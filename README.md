# Recogidas

Buscador para monitores: se escribe el nombre del alumno y muestra sus padres/tutores y las personas autorizadas a recogerlo.

- `build.mjs` lee el ERP (solo lectura), cifra los datos con la clave de acceso y genera `dist/`.
- `index.html` pide la clave, descifra en el navegador y busca en local.
- `.github/workflows/publicar.yml` lo regenera cada hora en horario escolar y lo publica en GitHub Pages.

Secretos del repositorio: `BSCD_ERP_USER`, `BSCD_ERP_PASS`, `RECOGIDAS_CLAVE`.
Los datos no se guardan en el repositorio y solo se publican cifrados. Para cambiar la clave: actualizar `RECOGIDAS_CLAVE` y lanzar el workflow a mano.
