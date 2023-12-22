<div align="center">
  <img src="https://coconucos.cs.hhu.de/lehre/bigdata/resources/img/hhu-logo.svg" width=300>

  [![Download](https://img.shields.io/static/v1?label=&message=pdf&color=EE3F24&style=for-the-badge&logo=adobe-acrobat-reader&logoColor=FFFFFF)](/../-/jobs/artifacts/master/file/document/thesis.pdf?job=latex)
</div>

# :notebook: &nbsp; Aufgabenbeschreibung

Standalone QUIC Implementierung in Rust
- Standalone Implementierung des QUIC Transportprotokolls auf Basis von UDP in Rust
1.72.0 mit folgenden Features
• Senden und Empfangen von QUIC-Paketen als Serverendpunkt
• Parsing und Ver-und Entschlüsselung der Header-und Payloaddaten
• Vollständig ausgeführter 1-RTT QUIC Handshake zwischen zwei Endpunkten
• TLS1.3 Handshake mithilfe von rustls
• Bedienung aller Frames im Payload, insbesondere Cryptoframes und Dataframes
- Als hauptsächliche Referenz dienen RFC’s 8999 - 9001 aufgrund mangelnder,
vergleichbarer Open-Source Implementationen in Rust
- Explizit zur Hilfe gezogen werden folgen Hilfsmittel
• Crate rustls { feature = “quic” } - für eine vollständige Implementierung von TLS1.3
• Crate octets - Rust zero-copy mutable Byte Buffer zur Hilfe beim Parsing
- Explizit ausgelassen werden aufgrund der zu knappen Zeitanforderung
• 0-RTT Packets
• Version Negotiation zwischen verschiedenen QUIC Versionen
• Connection Migration
• Advanced Flow Control
- Alles was weder als Feature noch als explizit ausgelassen aufgelistet ist, ist optional und
richtet sich nach meinem laufenden Fortschritt. Dazu zählen:
• Multithreading im Serverendpunkt
• QUIC Stream Implementierung, Simple Flow Control
• Client-Endpunkt Implementierung
- Ziel ist die Kommunikation mit einem in Python implementierten Client der nach dem
Handshake einzelne Datapackets als payload verschickt und auf deren ACK vom Server
wartet
• Python quic client ist implementiert mit Hilfe von aioquic
