#include "mainwindow.h"
#include <QtWidgets/qbuttongroup.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qradiobutton.h>
#include "./ui_mainwindow.h"


MainWindow::MainWindow(
    QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , encodeTypeGroup(new QButtonGroup)
    , encodeCodeMethodGroup(new QButtonGroup)
{
    ui->setupUi(this);
    initEncodeDecode();
}

MainWindow::~MainWindow()
{
    delete ui;
}

