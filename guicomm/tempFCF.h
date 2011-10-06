#ifndef TEMPFCF_H
#define TEMPFCF_H

struct tempFCF
{
        unsigned char dataOrCtrl;
        unsigned char destinationID_id;
        unsigned short int opcode;
        unsigned int paramterID;
        unsigned char senderID;
        unsigned int serialNum;
        void * parameterValue;
};

#endif // TEMPFCF_H
