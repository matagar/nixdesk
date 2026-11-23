import 'package:flutter/material.dart';

/// Colores de NixDesk. Único lugar donde se definen: el tema (`MyTheme` en
/// common.dart) y los pocos widgets con color propio los toman de acá.
///
/// Salen del ícono (flutter/assets/icon.svg): fondo carbón `#0B0F17`, borde azul
/// noche `#2A3650`, trazo claro `#D5DEEC` y acento naranja `#F38A20`.
///
/// Contrastes (WCAG 2.1, texto normal pide 4,5:1):
/// - `naranja` sobre `carbon` 7,7:1, sobre `noche` 6,9:1, sobre `nocheAlta` 6,0:1.
/// - `tinta` sobre `naranja` 7,7:1 (texto de los botones principales).
/// - blanco sobre `naranjaProfundo` 5,4:1; `naranjaProfundo` sobre blanco 5,4:1
///   y sobre `bruma` 4,8:1 (enlaces y acentos de texto en el tema claro).
/// - `niebla` sobre `carbon` 14,1:1; `nieblaMedia` sobre `noche` 7,1:1.
/// - `tinta` sobre `bruma` 16,9:1; `tintaMedia` sobre `bruma` 6,5:1.
/// El naranja pleno sobre blanco da 2,5:1: en el tema claro solo se usa en
/// trazos e indicadores, nunca en texto.
class NixColor {
  NixColor._();

  // Marca
  /// Acento: indicadores, íconos, bordes activos y texto sobre fondo oscuro.
  static const Color naranja = Color(0xFFF38A20);

  /// Naranja al pasar el mouse por un botón principal.
  static const Color naranjaClaro = Color(0xFFFFA347);

  /// Naranja para rellenos con contenido blanco y para texto sobre fondo claro.
  static const Color naranjaProfundo = Color(0xFFA85200);

  /// `naranjaProfundo` bajo el mouse (blanco encima: 7,3:1).
  static const Color naranjaHondo = Color(0xFF8A4300);

  /// Texto y dibujos sobre naranja; texto principal del tema claro.
  static const Color tinta = Color(0xFF0B0F17);

  // Tema oscuro
  /// Fondo de la ventana y del área de equipos.
  static const Color carbon = Color(0xFF0B0F17);

  /// Paneles, tarjetas y campos sobre el fondo.
  static const Color noche = Color(0xFF151B28);

  /// Elemento bajo el mouse o resaltado.
  static const Color nocheAlta = Color(0xFF1F2839);

  /// Bordes y separadores.
  static const Color borde = Color(0xFF2A3650);

  /// Borde con más presencia (campos, contornos al pasar el mouse).
  static const Color bordeFuerte = Color(0xFF42527A);

  /// Texto principal sobre oscuro.
  static const Color niebla = Color(0xFFD5DEEC);

  /// Texto secundario sobre oscuro.
  static const Color nieblaMedia = Color(0xFF9AA7BD);

  // Tema claro
  /// Fondo de la ventana.
  static const Color papel = Color(0xFFFFFFFF);

  /// Paneles, tarjetas y campos sobre el fondo.
  static const Color bruma = Color(0xFFEEF1F6);

  /// Elemento bajo el mouse o resaltado.
  static const Color brumaAlta = Color(0xFFDDE3EC);

  /// Bordes y separadores.
  static const Color bordeClaro = Color(0xFFC5CEDC);

  /// Texto secundario sobre claro.
  static const Color tintaMedia = Color(0xFF4A566B);

  // Estado
  static const Color listo = Color(0xFF32BEA6);
  static const Color aviso = Color(0xFFE2B33C);
  static const Color error = Color(0xFFE04F5F);

  /// Tonos para la cabecera de las tarjetas de equipos. Todos son oscuros para
  /// que el nombre (blanco al 70 %) se lea en los dos temas (mínimo 6,0:1).
  static const List<Color> tarjetas = [
    Color(0xFF22304A),
    Color(0xFF2B3A57),
    Color(0xFF1F3A4D),
    Color(0xFF33405C),
    Color(0xFF3A3350),
    Color(0xFF4A3524),
  ];

  /// Tono de tarjeta estable para un equipo (el mismo equipo, el mismo tono).
  static Color tarjeta(String semilla) {
    var h = 0;
    for (var i = 0; i < semilla.length; i++) {
      h = (h * 31 + semilla.codeUnitAt(i)) & 0x7FFFFFFF;
    }
    return tarjetas[h % tarjetas.length];
  }

  /// Fondo de una fila seleccionada; el texto del tema se lee encima.
  static Color seleccion(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark
          ? const Color(0xFF5A3410)
          : const Color(0xFFFFD9AE);

  /// Acento apto para texto e íconos según el tema en uso.
  static Color acento(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark
          ? naranja
          : naranjaProfundo;
}

/// Direcciones propias. NixDesk se basa en RustDesk (AGPL-3.0); el código fuente
/// de esta versión es público.
class NixUrl {
  NixUrl._();

  static const String fuente = 'https://github.com/matagar/nixdesk';
  static const String licencia =
      'https://github.com/matagar/nixdesk/blob/master/LICENCE';
  static const String rustdesk = 'https://github.com/rustdesk/rustdesk';
}
