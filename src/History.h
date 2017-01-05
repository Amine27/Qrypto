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


#ifndef HEADER_HISTORYWINDOW
#define HEADER_HISTORYWINDOW

#include <QtGui>
#include "Conversions.h"

class HistoryWindow : public QDialog
{
    Q_OBJECT

public slots:
    void grabOutputSlot();
    void grabInputSlot();
    void grabAllSlot();
    void clearSlot();

signals:
    void grabSignal(QString);

protected:
    void closeEvent(QCloseEvent *event);

public:
    HistoryWindow(QWidget *parent = 0);
    QTextEdit *textEdit;
    QPushButton *clear;

private:

    Conversion *conv;

    QPushButton *grabInput;
    QPushButton *grabOutput;
    QPushButton *grabAll;
    //QPushButton *closeButton;
};

#endif
