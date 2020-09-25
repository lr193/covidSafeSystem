//
//Sector 1 - Block 4
//
//      BYTE Pos    Value     Meaning
//
//          0        0x01       Registered User
//          0        0x00       Visitor ID
//
//          1        0x01       User can access library
//          1        0x00       User cannot access the library
//
//          2        0x01       User can access Building A
//          2        0x00       User cannot access Building A
//
//          3        0x01       User can access Building B
//          3        0x00       User cannot access Building B



#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

int visitorID = 00000234; //Upto 9,999,999 visitors can be registered in the system

int ones;
int tens;
int hundreds;
int thousands;
int tenThousands;
int lakhs;
int millions;

const int echopin1 = 2;   
const int trigpin1 = 3; 
const int echopin2 = 4;
const int trigpin2 = 5;

long inDuration, outDuration, inDistance, outDistance;

int inCount = 0;
int outCount = 0;
int full = 0;
int maxHeads = 10;
int ledPin = 6;
int numberIn = 0;


void setup() {
  Serial.begin(9600); // Initialize serial communications with the PC
  while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();        // Init SPI bus
  mfrc522.PCD_Init(); // Init MFRC522 card

  // Prepare the key (used both as key A and as key B)
  // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  Serial.println(F("Creating new Visitor ID"));
}

/**
   Main loop.
*/
void loop() {
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial())
    return;

  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Visitor ID is: ")); Serial.println(visitorID);
  //    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  //  Serial.println();
  Serial.println();
  //    Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  //    Serial.println(mfrc522.PICC_GetTypeName(piccType));

  // Check for compatibility
  if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("Invalid ID presented! Please contact security for any inquiries. "));
    return;
  }

  // In this sample we use the second sector,
  // that is: sector #1, covering block #4 up to and including block #7
  byte no_access = 0x00;
  byte allow_access = 0x01;
  byte visitor = 0x00;
  byte user = 0x01;

  byte sector         = 1;
  byte blockAddr      = 4; //Block to store the user's ID
  byte dataBlock[]    = {
    visitor, no_access, allow_access, allow_access,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  }; //The first byte for visitor ID is 0

  byte trailerBlock   = 7;
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);


  // Authenticate using key B
  //  Serial.println(F("Authenticating again using key B..."));
  Serial.println(F("Creating Visitor ID"));Serial.println();
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  //  Storing the Visitor ID in the RFID

  ones = (visitorID % 10);
  tens = ((visitorID / 10) % 10);
  hundreds = ((visitorID / 100) % 10);
  thousands = ((visitorID / 1000) % 10);
  tenThousands = ((visitorID / 10000) % 10);
  lakhs = ((visitorID / 100000) % 10);
  millions = (visitorID / 100000);

  byte IdBlockAddr      = 6; //Block to store the user's ID
  byte VisitorIdBlock[16]    = {
    (byte)millions, (byte)lakhs, (byte)tenThousands, (byte)thousands,
    (byte)hundreds, (byte)tens, (byte)ones, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  // Write visitorID to the sector 1 block 6
  Serial.print(F("Writing data (Visitor ID Number) into block ")); Serial.print(IdBlockAddr);
  Serial.println(F(" ..."));
  dump_byte_array(VisitorIdBlock, 16); Serial.println();

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(IdBlockAddr, VisitorIdBlock, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error creating Visitor ID, Please try again!"));
    //        Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  visitorID++;

  Serial.println("Visitor ID successfully written");
  Serial.println();

  //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

  // Write data to the block
  Serial.print(F("Writing permission data into RFID block ")); Serial.print(blockAddr);
  Serial.println(F(" ..."));
  dump_byte_array(dataBlock, 16);

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddr, dataBlock, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error creating Visitor ID, Please try again!"));
    //        Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  Serial.println();
  Serial.print(F("permission data written successfully"));
  Serial.println();


  // Read data from the block (again, should now be what we have written)
  //  Serial.print(F("Reading data from block ")); Serial.print(blockAddr);
  //  Serial.println(F(" ..."));
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error reading Visitor ID, Please try again!"));
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  //  Serial.print(F("Data in block ")); Serial.print(blockAddr); Serial.println(F(":"));
  //  dump_byte_array(buffer, 16); Serial.println();

  //  checkIfVisitor(buffer);
  Serial.println();
  displayAllowedBuildings(buffer);
  Serial.println();


  // Check that data in block is what we have written
  // by counting the number of bytes that are equal
  Serial.println(F("Checking result..."));
  byte count = 0;
  for (byte i = 0; i < 16; i++) {
    // Compare buffer (= what we've read) with dataBlock (= what we've written)
    if (buffer[i] == dataBlock[i])
      count++;
  }
  Serial.print(F("Number of bytes that match = ")); Serial.println(count);
  if (count == 16) {
    Serial.println(F("Visitor ID Created :-)"));
  } else {
    Serial.println(F("Failure, no match :-("));
    Serial.println(F("  perhaps the write didn't work properly..."));
  }
  Serial.println();

  // Dump the sector data
  Serial.println(F("Current data in sector:"));
  mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
  Serial.println();

  // Halt PICC
  mfrc522.PICC_HaltA();
  // Stop encryption on PCD
  mfrc522.PCD_StopCrypto1();
}

void displayAllowedBuildings(byte* buffer) {

  Serial.println("The list of buildings visitor has access to: " );

  if (buffer[1] == 1) {
    Serial.println("Library");
  }else{
    Serial.println("No access to the library");
  }

  if (buffer[2] == 1) {
    Serial.println("A");
  }

  if (buffer[3] == 1) {
    Serial.println("B");
  }

}


void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}
