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
#include <Servo.h>

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;
Servo servo;


int userID = 0000005; //Upto 9,999,999 users can be registered in the system
String username = "Rashmika Opatha";

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
boolean validID = false;

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

  pinMode(trigpin1, OUTPUT);
  pinMode(trigpin2, OUTPUT);
  pinMode(echopin1, INPUT);
  pinMode(echopin2, INPUT);

  servo.attach(8);
  servo.write(0);
}

void loop() {

  //==============================================================================================================================
  //Ultrasonic sensor code
  digitalWrite(trigpin1, LOW);
  delayMicroseconds(3);
  digitalWrite(trigpin1, HIGH);
  delayMicroseconds(5);
  digitalWrite(trigpin1, LOW);
  inDuration = pulseIn(echopin1, HIGH);

  digitalWrite(trigpin2, LOW);
  delayMicroseconds(3);
  digitalWrite(trigpin2, HIGH);
  delayMicroseconds(5);
  digitalWrite(trigpin2, LOW);
  outDuration = pulseIn(echopin2, HIGH);

  inDistance = inDuration * 0.034 / 2;
  outDistance = outDuration * 0.034 / 2;
  
  if (inDistance < 10) {
    inCount++;
    Serial.print("Number in: ");
    Serial.println(inCount);
    delay(100);
  }

  if (outDistance < 10) {
    inCount--;
    Serial.print("Number in: ");
    Serial.println(inCount);
    delay(100);
  }

  delay(200);

  if (inCount >= 5) {
    //Library Full
    full = 1;
    digitalWrite(ledPin, HIGH);
    Serial.println("LIBRARY IS FULLL");
    delay(100);
  } else {
    full = 0;
    digitalWrite(ledPin, LOW);
    delay(100);
  }
  // End Ultrasonic sensor code
  //==============================================================================================================================


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
  byte trailerBlock   = 7;
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);


  // Authenticate using key B

  Serial.println(F("Creating User ID")); Serial.println();
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Read data from the block (again, should now be what we have written)

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Error reading User ID, Please try again!"));
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }


  if (buffer[1] == 0 ) {
    Serial.println(F("Sorry! You do not have permission enter this building"));
  } else {
    validID = true;
    Serial.println(F("Welcome to the library!"));
    Serial.println(validID);
    Serial.println(full);
  }

  Serial.println();

  int tempInCount = inCount;

  if (full == 0 && validID == true) {
    //    Open the gate

    Serial.println("Gate Opened");
    servo.write(180);
  }else{
    Serial.println("Library is full");
  }

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
  } else {
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
