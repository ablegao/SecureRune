#include "mainwindow.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include <QMutex>
#include <QDateTime>
#include <QMetaObject>
#include "mainwindow.h"

// Global Qt message handler that forwards messages to MainWindow::showLogs
void qtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    // Format method string based on message type
    QString method;
    switch (type) {
    case QtDebugMsg:
        method = "DEBUG";
        break;
    case QtInfoMsg:
        method = "INFO";
        break;
    case QtWarningMsg:
        method = "WARNING";
        break;
    case QtCriticalMsg:
        method = "CRITICAL";
        break;
    case QtFatalMsg:
        method = "FATAL";
        break;
    default:
        method = "UNKNOWN";
    }

    // Always print to stderr as well
    QTextStream ts(stderr);
    ts << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") << " [" << method << "] " << msg << "\n";

    // Forward to MainWindow if available
    MainWindow *w = MainWindow::instance();
    if (w) {
        // Use queued connection so we are thread-safe and don't block the sender thread
        QMetaObject::invokeMethod(w, "showLogs", Qt::QueuedConnection,
                                  Q_ARG(QString, method), Q_ARG(QString, msg));
    }

    if (type == QtFatalMsg) {
        abort();
    }
}

int main(
    int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Install message handler early so messages during startup are captured
    qInstallMessageHandler(qtMessageHandler);

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "SecureRune_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }
    MainWindow w;
    w.show();
    return a.exec();
}
