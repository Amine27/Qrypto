// This file is part of the Qrypto project
// Copyright (C) 2008-2010 Amine Roukh <amineroukh@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; If not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#include "History.h"


using namespace std;

HistoryWindow::HistoryWindow(QWidget *parent) : QDialog(parent)
{
    conv = new Conversion();

    textEdit = new QTextEdit;
    textEdit->setReadOnly(true);

    grabInput = new QPushButton(tr("Grab &Input"));
    connect(grabInput, SIGNAL(clicked()), this, SLOT(grabInputSlot()));
    grabOutput = new QPushButton(tr("Grab &Output"));
    connect(grabOutput, SIGNAL(clicked()), this, SLOT(grabOutputSlot()));
    grabAll = new QPushButton(tr("Grab &All"));
    connect(grabAll, SIGNAL(clicked()), this, SLOT(grabAllSlot()));
    clear = new QPushButton(QIcon(":/data/clear-history.png"), tr("&Clear"));
    clear->setEnabled(false);
    connect(clear, SIGNAL(clicked()), this, SLOT(clearSlot()));

    //closeButton = new QPushButton(tr("&Close"));
    //connect(closeButton, SIGNAL(clicked()), this, SLOT(accept()));

    QHBoxLayout *layoutBut = new QHBoxLayout;
    layoutBut->addWidget(grabInput);
    layoutBut->addWidget(grabOutput);
    layoutBut->addWidget(grabAll);
    layoutBut->addWidget(clear);

    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(textEdit);
    layout->addLayout(layoutBut);
    setLayout(layout);


    QSettings settings(tr("Qrypto", "Qt apps"));
    QString msg64 = settings.value("Memo/MemoData").toString();

    string msg = conv->Base64DecodeFun(msg64);
    textEdit->setText(QString::fromStdString(msg));

    setWindowTitle(tr("Memo Aera"));
}

void HistoryWindow::grabInputSlot()
{
    emit grabSignal("Input");
}

void HistoryWindow::grabOutputSlot()
{
    emit grabSignal("Output");
}

void HistoryWindow::grabAllSlot()
{
    emit grabSignal("All");
}

void HistoryWindow::clearSlot()
{
    textEdit->clear();
    clear->setEnabled(false);
}

void HistoryWindow::closeEvent(QCloseEvent *event)
{
    string msg = conv->Base64EncodeFun(textEdit->toPlainText());

    QSettings settings(tr("Qrypto", "Qt apps"));
    settings.setValue("Memo/MemoData", QString::fromStdString(msg));
    event->accept();
}
