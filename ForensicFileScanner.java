package org.example;
import java.io.*;
import java.util.*;

public class ForensicFileScanner {


    private static final Map<String, String> SIGNATURES = new HashMap<>();


        // Ključ -> magic bytes  ,  Vrednost -> pravi tip fajla
    static {    //u static bloku zato što se mora inicijalizovati jednom pri učitavanju klase  - zajednička za celu klasu
        SIGNATURES.put("FFD8FF", "JPEG Slika");
        SIGNATURES.put("89504E47", "PNG Slika");
        SIGNATURES.put("25504446", "PDF Dokument");
        SIGNATURES.put("4D5A", "Windows EXE fajl");
        SIGNATURES.put("504B0304", "ZIP Arhiva");
        SIGNATURES.put("52617221", "RAR Arhiva");
        SIGNATURES.put("494433", "MP3 Audio");
        SIGNATURES.put("424D", "BMP Slika");
        SIGNATURES.put("47494638", "GIF Slika");
        SIGNATURES.put("1F8B08", "GZIP Arhiva");
    }

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("   FORENZIČKI FILE SIGNATURE SCANNER   ");
        System.out.println("========================================\n");

        Scanner input = new Scanner(System.in);

        while (true) {
            System.out.println("\n1. Skeniraj pojedinačni fajl");
            System.out.println("2. Skeniraj ceo folder");
            System.out.println("3. Kreiraj test fajlove za demonstraciju");
            System.out.println("4. Izlaz");
            System.out.print("\nIzaberite opciju (1-4): ");

            String choice = input.nextLine();

            switch (choice) {
                case "1":
                    scanSingleFile(input);
                    break;
                case "2":
                    scanFolder(input);
                    break;
                case "3":
                    createTestFiles();
                    break;
                case "4":
                    System.out.println("\nHvala što koristite Scanner!");
                    input.close();
                    return;
                default:
                    System.out.println("Nevažeći izbor. Pokušajte ponovo.");
            }
        }
    }

    // Analiza jednog fajla
    private static void scanSingleFile(Scanner input) {  // za unos podataka
        System.out.print("\nUnesite putanju do fajla: ");
        String path = input.nextLine().replace("\"", ""); // uklanja navodnike

        File file = new File(path); // Creates a new File instance by converting the given pathname string

        if (!file.exists()) {  //specific file or directory, identified by its path, is present and accessible on a computer's storage
            System.out.println("X Fajl ne postoji!");
            return;
        }

        System.out.println("\n" + "=".repeat(50));
        System.out.println("ANALIZA FAJLA: " + file.getName());  // Returns the name of the file or directory denoted by this abstract pathname.
        System.out.println("=".repeat(50));

        String extension = getFileExtension(file);
        System.out.println("Ekstenzija: " + (extension.isEmpty() ? "Nema" : "." + extension));

        String realType = detectFileType(file);
        System.out.println("Stvarni tip: " + realType);

        if (!extension.isEmpty() && !realType.contains("Nepoznato")) {
            if (isExtensionMismatch(extension, realType)) {      // proverava da li se ekstenzija fajla poklapa sa njegovim stvarnim tipom
                System.out.println(" !!!  UPOZORENJE: Ekstenzija se NE poklapa sa stvarnim tipom!");
            } else {
                System.out.println("✓ Ekstenzija i tip se poklapaju.");
            }
        }

        // Prikaz heksadecimalnog header-a
        System.out.println("\nHeksadecimalni header:");
        displayFileHeader(file);
    }

    // Analiza celog foldera
    private static void scanFolder(Scanner input) {
        System.out.print("\nUnesite putanju do foldera: ");
        String path = input.nextLine().replace("\"", "");

        File folder = new File(path);

        if (!folder.exists() || !folder.isDirectory()) {
            System.out.println("X Folder ne postoji!");
            return;
        }

        File[] files = folder.listFiles();  //  retrieve a list of files and directories within a specified directory
        if (files == null || files.length == 0) {
            System.out.println("  Folder je prazan.");
            return;
        }

        System.out.println("\n" + "=".repeat(60));
        System.out.println("SKENIRANJE FOLDERA: " + folder.getName());
        System.out.println("=".repeat(60));

        int suspiciousCount = 0;
        int totalFiles = 0;

        System.out.printf("\n%-25s %-20s %s\n", "FAJL", "TIP", "STATUS");
        // Priprema kolone da svi redovi ispod budu lepo poravnati , kao neka tabela.
        System.out.println("-".repeat(60));

        // tabela
        for (File file : files) {
            if (file.isFile()) {  //A file is normal if it is not a directory and, in addition, satisfies other system-dependent criteria.
                totalFiles++;
                String extension = getFileExtension(file); // Gleda ime fajla
                String realType = detectFileType(file);  // Gleda sadržaj fajla

                String status = " OK";
                if (!extension.isEmpty() && !realType.contains("Nepoznato") &&
                        isExtensionMismatch(extension, realType)) {
                    status = " SUMNJIVO !!! ";
                    suspiciousCount++;
                }

                String fileName = file.getName();  //  samo da bi bilo lepse u tabeli
                if (fileName.length() > 22) {
                    fileName = fileName.substring(0, 19) + "...";
                }

                System.out.printf("%-25s %-20s %s\n", fileName, realType, status);
            }
        }

        System.out.println("\n" + "=".repeat(60));
        System.out.println("REZIME:");
        System.out.println("Ukupno fajlova: " + totalFiles);
        System.out.println("Sumnjivih fajlova: " + suspiciousCount);
    }

    // Kreiranje test fajlova za demonstraciju
    private static void createTestFiles() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("KREIRANJE TEST FAJLOVA");
        System.out.println("=".repeat(50));

        File testFolder = new File("test_forensics");  // Pravi objekat
        if (!testFolder.exists()) {
            testFolder.mkdir();  // Ako folder ne postoji, ovo ga kreira
        }

        try {
            // 1. EXE prekriven kao TXT (sumnjivo)
            // FileOutputStream - creates a file output stream to write to the file represented by the specified File object
            FileOutputStream fos1 = new FileOutputStream(new File(testFolder, "cisti_kod.txt"));
            fos1.write(0x4D); // M u ASCII
            fos1.write(0x5A); // Z u ASCII
            fos1.write("Ovo je EXE fajl prekriven kao tekst".getBytes());  // MZ je EXE file signature

            // NE menjamo postojeći TXT u EXE  već  se kreira fajl sa .txt imenom  ali mu ubacuješ EXE magic number (MZ)
            /*
            * Operativni sistem prilikom izvršavanja fajla proverava njegov sadržaj (magic number),
            *  tako da fajl sa TXT ekstenzijom ali EXE potpisom, može biti izvršen kao program ako se pokrene na odgovarajući način.
            *
            * “double extension” trik
            *
            * */
            fos1.close();

            // 2. PDF prekriven kao JPG (sumnjivo)
            FileOutputStream fos2 = new FileOutputStream(new File(testFolder, "slika.jpg"));
            fos2.write(0x25); // %
            fos2.write(0x50); // P
            fos2.write(0x44); // D
            fos2.write(0x46); // F
            fos2.write("PDF dokument prekriven kao slika".getBytes());
            fos2.close();

            // 3. ZIP prikriven kao DOC (sumnjivo)
            FileOutputStream fos3 = new FileOutputStream(new File(testFolder, "izvestaj.doc"));
            fos3.write(0x50); // P
            fos3.write(0x4B); // K
            fos3.write(0x03);
            fos3.write(0x04);
            // 0x50 0x4B 0x03 0x04 - magic number za ZIP fajl.
            fos3.write("ZIP arhiva prekrivena kao Word dokument".getBytes());
            fos3.close();

            // 4. Normalan JPEG (OK)
            FileOutputStream fos4 = new FileOutputStream(new File(testFolder, "normalna_slika.jpg"));
            fos4.write(0xFF);
            fos4.write(0xD8);
            fos4.write(0xFF);
            fos4.write("Ovo je prava JPEG slika".getBytes());
            fos4.close();

            // 5. Normalan tekst (OK)
            FileWriter fw = new FileWriter(new File(testFolder, "beleške.txt"));
            fw.write("Ovo je normalan tekstualni fajl.\nKreirao: Test Korisnik");
            fw.close();

            // opis sta smo uradili
            System.out.println("✓ Kreirano 5 test fajlova!");
            System.out.println("✓ Lokacija: " + testFolder.getAbsolutePath());
            System.out.println("\nTest fajlovi:");
            System.out.println("1. cisti_kod.txt   -> EXE fajl (sumnjivo)");
            System.out.println("2. slika.jpg      -> PDF dokument (sumnjivo)");
            System.out.println("3. izvestaj.doc   -> ZIP arhiva (sumnjivo)");
            System.out.println("4. normalna_slika.jpg -> JPEG slika (OK)");
            System.out.println("5. beleške.txt    -> Tekstualni fajl (OK)");

        } catch (IOException e) {  // input/output exception
            System.out.println("X Greška pri kreiranju fajlova: " + e.getMessage());
        }
    }

    // Dobijanje ekstenzije fajla
    private static String getFileExtension(File file) {
        String fileName = file.getName();   //Returns the name of the file or directory denoted by this abstract pathname.
        int dotIndex = fileName.lastIndexOf('.'); // pozicija tacke

        if (dotIndex > 0 && dotIndex < fileName.length() - 1) {
            return fileName.substring(dotIndex + 1).toLowerCase();  // uzima sve posle te tačke
        }
        return "";   // Ako nema tačke
    }

    // Detekcija stvarnog tipa fajla
    private static String detectFileType(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {  // A FileInputStream obtains input bytes from a file in a file system.
            byte[] header = new byte[8];
            int bytesRead = fis.read(header);

            if (bytesRead < 2) {
                return "Nepoznato (fajl prekratak)";
            }

            // Konvertuj u heksadecimalni string
            StringBuilder hexBuilder = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                hexBuilder.append(String.format("%02X", header[i]));   //  Pretvaranje bajtova u heksadecimalni string
            }
            String hexHeader = hexBuilder.toString();


            // Poređenje sa poznatim signature-ima
            for (Map.Entry<String, String> entry : SIGNATURES.entrySet()) {  // .entrySet() -> Returns a Set view of the
                                                                            // mappings contained in this map.
                if (hexHeader.startsWith(entry.getKey())) {
                    return entry.getValue();
                }
            }

            return "Nepoznato tip";

        } catch (IOException e) {
            return "Greška pri čitanju";
        }
    }

    // Provera da li se ekstenzija i tip poklapaju
    private static boolean isExtensionMismatch(String extension, String realType) {

        // Mapa validnih ekstenzija
       //  Za svaki poznati tip fajla čuvamo koje ekstenzije su dozvoljene.
        Map<String, String[]> validExtensions = new HashMap<>();
        validExtensions.put("JPEG Slika", new String[]{"jpg", "jpeg", "jpe"});  // string arr
        validExtensions.put("PNG Slika", new String[]{"png"});
        validExtensions.put("PDF Dokument", new String[]{"pdf"});
        validExtensions.put("Windows EXE fajl", new String[]{"exe", "com", "dll"});
        validExtensions.put("ZIP Arhiva", new String[]{"zip"});
        validExtensions.put("RAR Arhiva", new String[]{"rar"});
        validExtensions.put("MP3 Audio", new String[]{"mp3"});
        validExtensions.put("BMP Slika", new String[]{"bmp"});
        validExtensions.put("GIF Slika", new String[]{"gif"});

        if (!validExtensions.containsKey(realType)) {
            return false; // Nemamo informacije za ovaj tip , pretpostavljamo da ne postoji
        }

        for (String ext : validExtensions.get(realType)) {   // Ako je realType = "JPEG Slika", niz je {"jpg","jpeg","jpe"}
            if (ext.equalsIgnoreCase(extension)) {   // "PDF".equalsIgnoreCase("pdf") -> true
                return false; // poklapaju se, fajl nije sumnjiv
            }
        }

        return true; // Ne poklapa se - ima neusklađenosti
    }

    // Prikaz heksadecimalnog header-a
    private static void displayFileHeader(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[16];
            int bytesRead = fis.read(header);

            System.out.print("Hex: ");
            for (int i = 0; i < bytesRead; i++) {
                System.out.printf("%02X ", header[i]);
                if (i == 7) System.out.print(" ");
            }
            System.out.println();

        } catch (IOException e) {
            System.out.println("Greška pri čitanju header-a");
        }
    }
}
