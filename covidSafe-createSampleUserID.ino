//
//      Sector 1 - Block 4
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

int userID = 0000005; //Upto 9,999,999 users can be registered in the system
String username = "Rashmika Opatha";

int ones;
int tens;
int hundreds;
int thousands;
int tenThousands;
int lakhs;
int millions;

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

  Serial.println(F("Creating new sample User ID"));
}


void loop() {
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial())
    return;

  Serial.print(F("User ID is: ")); Serial.println(userID);
  Serial.println();

  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);

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
  byte blockAddr      = 4;
  byte dataBlock[]    = {
    user, allow_access, allow_access, allow_access,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  }; //The first byte for User ID is 1

  byte trailerBlock   = 7;
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);


  // Authenticate using key B

  Serial.println(F("Creating User ID"));Serial.println();
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  //  Storing the User ID in the RFID

  ones = (userID % 10);
  tens = ((userID / 10) % 10);
  hundreds = ((userID / 100) % 10);
  thousands = ((userID / 1000) % 10);
  tenThousands = ((userID / 10000) % 10);
  lakhs = ((userID / 100000) % 10);
  millions = (userID / 100000);

  byte IdBlockAddr      = 6; //Block to store the user's ID
  byte userIDBlock[16]    = {
    (byte)millions, (byte)lakhs, (byte)tenThousands, (byte)thousands,
    (byte)hundreds, (byte)tens, (byte)ones, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  // Write userID to the sector 1 block 6
  Serial.print(F("Writing data (User ID Number) into block ")); Serial.print(IdBlockAddr);
  Serial.println(F(" ..."));
//  dump_byte_array(userIDBlock, 16); Serial.println();

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(IdBlockAddr, userIDBlock, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error creating User ID, Please try again!"));
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  userID++;

  Serial.println("User ID successfully written");
  Serial.println();

  //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

  // Write data to the block
  Serial.print(F("Writing permission data into RFID block ")); Serial.print(blockAddr);
  Serial.println(F(" ..."));
//  dump_byte_array(dataBlock, 16);

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddr, dataBlock, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error creating User ID, Please try again!"));
    //        Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  Serial.println();
  Serial.print(F("permission data written successfully"));
  Serial.println();


//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//Storing the user name in RFID

//Converting String into a char arrray

char nameArr[username.length()];

for(int i = 0; i < username.length(); i++){
  nameArr[i] = username[i];
}
Serial.println(username.length());

//username.length()
byte nameInByte[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };;

for(int i = 0; i < 16; i++){
  nameInByte[i] = (byte)nameArr[i];
}

for(int i = 0; i < sizeof(nameInByte); i++){
//  Serial.print(nameInByte[i]);
}
//Serial.println();

for(int i = 0; i < sizeof(nameInByte); i++){
//  Serial.print((char)nameInByte[i]);
}


  byte usernameBlockAddr      = 5; //Block to store the user's name
//  byte userNameBlock[16]    = {
//    (byte)millions, (byte)lakhs, (byte)tenThousands, (byte)thousands,
//    (byte)hundreds, (byte)tens, (byte)ones, 0x00,
//    0x00, 0x00, 0x00, 0x00,
//    0x00, 0x00, 0x00, 0x00
//  };

  // Write userID to the sector 1 block 6
//  Serial.print(F("Writing data (User ID Number) into block ")); Serial.print(usernameBlockAddr);
//  Serial.println(F(" ..."));
  dump_byte_array(nameInByte, 16); Serial.println();

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(usernameBlockAddr, nameInByte, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error creating User ID, Please try again!"));
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }


//Reading the user name from the RFID
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(usernameBlockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error reading User ID, Please try again!"));
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  char arrToStoreName[sizeof(buffer)];
  
  for(int i =0; i<sizeof(buffer); i++){
    arrToStoreName[i] = (char)buffer[i];  
  }

  Serial.print("Welcome ");
  
  for(int i =0; i<16; i++){
    Serial.print(arrToStoreName[i]);
  }

  Serial.print(" !");
  Serial.println();

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


  // Read data from the block (again, should now be what we have written)

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error reading User ID, Please try again!"));
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  
  Serial.println();
  displayAllowedBuildings(buffer);
  Serial.println();


  // Check that data in block is what we have written
  // by counting the number of bytes that are equal
//  Serial.println(F("Checking result..."));
  byte count = 0;
  for (byte i = 0; i < 16; i++) {

    if (buffer[i] == dataBlock[i])
      count++;
  }
//  Serial.print(F("Number of bytes that match = ")); Serial.println(count);
  if (count == 16) {
    Serial.println(F("User ID Created :-)"));
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

  Serial.println("The list of buildings User has access to: " );

  if (buffer[1] == 1) {
    Serial.println("Can access the Library");
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
