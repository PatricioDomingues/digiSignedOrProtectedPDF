# digiSignedOrProtectedPDF
File ingest module in jython for autopsy 4.4.1 or above.

The digiSigned|ProtectedPDF module is a file ingest jython-based module for the Autopsy software.
It provides two main services for PDF files:
1) Identifies the PDF files that are digitally signed (digital signature refers to the cryptographically-based signature of documents. It does **not** refer to have images of physical signatures in a document.)

2) Identifies the PDF files which some kind of user-level protection. Specifically, the module flags as interesting files PDF files that forbids the "document assembly" and "document modify".

The digiSigned|ProtectedPDF module depends on two excellent external tools (not included in this repository):
- JSignPDF (http://jsignpdf.sourceforge.net)
- ExifTool (https://sno.phy.queensu.ca/~phil/exiftool/)

The digiSigned|ProtectedPDF module requires that the full path of these two tools is properly configured. This is done in the settings interface (see INSTALL.PDF).


