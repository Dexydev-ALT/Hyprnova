# QML load verification: instantiate the full console UI offscreen with stub
# context properties. Real Qt6, real parser, real type resolution. Backend
# property reads fail by design (the stub is empty) -- only SYNTAX / TYPE /
# MODULE errors mean the QML is actually broken.
import os, re, sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_LOGGING_RULES", "*.debug=false")

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine

app = QGuiApplication(sys.argv[:1])
engine = QQmlApplicationEngine()

from PySide6.QtCore import QObject


class StubBackend(QObject):
    pass


ctx = engine.rootContext()
STUB = StubBackend()
ctx.setContextProperty("backend", STUB)
ctx.setContextProperty("agentSocket", "/run/hyprnova/gui.sock")
ctx.setContextProperty("themeName", "midnight")
ctx.setContextProperty("refreshHz", 4)
ctx.setContextProperty("showKernelEvents", False)
ctx.setContextProperty("guiVersion", "1.0.0-test")
ctx.setContextProperty("windowVibrancy", True)

warnings = []
engine.warnings.connect(lambda ws: warnings.extend(w.toString() for w in ws))

engine.addImportPath(os.path.abspath("gui/qml"))
engine.load(QUrl.fromLocalFile(os.path.abspath("gui/qml/main.qml")))

# main.qml keeps ONE page alive at a time (lazy Loaders), so loading main.qml
# alone never instantiates the non-dashboard pages. Instantiate every page and
# every component explicitly: bindings and type resolution run for real, and
# only syntax/type/module errors count as failures. Property noise from the
# empty stub (and null Window.window in standalone components) is expected.
import glob
extras = (sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(
              __file__)), "..", "gui", "qml", "pages", "*.qml"))) +
          sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(
              __file__)), "..", "gui", "qml", "components", "*.qml"))))
for qml in extras:
    if qml.endswith("qmldir"):
        continue
    engine.load(QUrl.fromLocalFile(os.path.abspath(qml)))

QTimer.singleShot(400, app.quit)
app.exec()

BAD = re.compile(
    r"SyntaxError|Unexpected token|is not (?:a type|n object type)|"
    r"Module not found|Cannot load|no such file|Failed to (?:create|load|import)|"
    r"Cannot assign|Duplicate property|Invalid (?:property|component)|"
    r"was not found|does not have a property|Unknown (?:method|component)",
    re.IGNORECASE,
)

real = [w for w in warnings if BAD.search(w)]
noise = [w for w in warnings if w not in real]

print(f"--- load result: root objects = {len(engine.rootObjects())}")
print(f"--- total warnings: {len(warnings)}  (expected stub noise: {len(noise)})")
if real:
    print(f"--- REAL QML ERRORS: {len(real)}")
    for w in real[:3]:
        print("   !", w[:400])
    sys.exit(1)
print("--- NO syntax/type/module errors")
sys.exit(0)
