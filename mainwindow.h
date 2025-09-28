#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtCore/qmap.h>
#include <QMainWindow>
#include <QtWidgets>
QT_BEGIN_NAMESPACE
namespace Ui {

class MainWindow;

}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encode_input_plaintext_textChanged();
    void on_encodetype_radio_changed();

private:
    Ui::MainWindow *ui;

    // encode/decode
    QButtonGroup *encodeTypeGroup;
    QButtonGroup *encodeCodeMethodGroup;
    void initEncodeDecode();
    QMap<QString, QString> encodeCustomAlphabetMap;

    // hex


    //



};
#endif // MAINWINDOW_H
