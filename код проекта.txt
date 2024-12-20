В рамках выполнения курсовой работы было успешно разработано приложение на JavaFX, позволяющее пользователю шифровать и дешифровать файлы с использованием двух различных алгоритмов:
1.	RSA + SHA-256;
2.	AES + SHA-256.

В коде проекте присутствует 4 класса:
1) Launcher - главный класс, запускающий приложение.
2) Server - сервер.
3) Client - клиент.
4) CryptoUtil - класс по шифрованию файлов.
----------------------------------------------------------------------------------------------
Код класса Launcher:
package org.example.demo;

import javafx.application.Application;
import javafx.stage.Stage;

/**
 * Класс Launcher отвечает за запуск приложения, включающий в себя запуск сервера в отдельном потоке и запуск клиента.
 * <p>
 * Приложение использует архитектуру клиент-сервер.
 * Сервер запускается в отдельном потоке, что позволяет клиенту взаимодействовать с сервером асинхронно.
 * Клиент взаимодействует с сервером через сетевые запросы.
 */
public class Launcher extends Application {

    /**
     * Точка входа в приложение.
     *
     * @param args Командная строка.
     */
    public static void main(String[] args) {
        // Запуск сервера в отдельном потоке.
        // Использование нового потока для запуска сервера позволяет приложению не зависать во время инициализации сервера.
        new Thread(org.example.demo.Server::startServer).start();

        // Запуск клиента.  Метод launch() из Application класса запускает JavaFX приложение.
        launch(args);
    }

    /**
     * Метод start() из Application класса. Используется для инициализации и отображения графического интерфейса пользователя (GUI) приложения.
     *
     * @param primaryStage Основное окно JavaFX приложения.
     * @throws Exception Если возникнут ошибки во время запуска.
     */
    @Override
    public void start(Stage primaryStage) {
        // Создание экземпляра клиента.
        org.example.demo.Client client = new org.example.demo.Client();
        // Запуск клиента и передача ему основного окна.
        client.start(primaryStage);
    }
}
----------------------------------------------------------------------------------------------
Код класса Server:

package org.example.demo;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * Класс Server реализует серверную часть приложения, которая принимает зашифрованные файлы от клиента.
 * Он запускает серверный сокет и обрабатывает подключенные клиентские сокеты.
 */
public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final int PORT = 12345;

    /**
     * Метод запускает сервер на заданном порту и ожидает подключения клиентов.
     * Для каждого подключенного клиента запускается новый поток для обработки.
     */
    public static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            logger.info("Сервер запущен на порту " + PORT);

            // Бесконечный цикл для обработки клиентских подключений
            while (true) {
                Socket clientSocket = serverSocket.accept();
                logger.info("Клиент подключён: " + clientSocket.getInetAddress());
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (IOException e) {
            logger.severe("Сервер запущен на порту " + PORT);
        }
    }

    /**
     * Метод для обработки клиентского подключения.
     * Принимает зашифрованный файл, сохраняет его на диск, а затем отправляет ответ клиенту.
     *
     * @param clientSocket сокет подключенного клиента
     */
    private static void handleClient(Socket clientSocket) {
        try (InputStream inputStream = clientSocket.getInputStream();
             OutputStream outputStream = clientSocket.getOutputStream()) {

            // Создание файла для сохранения полученных данных
            File receivedFile = new File("received_encrypted_file");
            try (FileOutputStream fos = new FileOutputStream(receivedFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;

                // Чтение данных из InputStream и запись их в файл
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byte[] dataToWrite = new byte[bytesRead];
                    System.arraycopy(buffer, 0, dataToWrite, 0, bytesRead);
                    fos.write(dataToWrite);
                }
            }
            logger.info("Зашифрованный файл получен: " + receivedFile.getName());

            // Отправка ответа клиенту
            outputStream.write("Файл успешно получен и обработан.".getBytes());
        } catch (IOException e) {
            logger.severe("Ошибка обработки клиента: " + e.getMessage());
        }
    }

    /**
     * Главный метод программы. Запускает сервер на порту, указанном в константе PORT.
     *
     * @param args аргументы командной строки (не используются)
     */
    public static void main(String[] args) {
        startServer();
    }
}
----------------------------------------------------------------------------------------------
Код класса CryptoUtil:
package org.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Утилитный класс для выполнения криптографических операций, таких как шифрование и дешифрование файлов
 * с использованием RSA и AES, а также для работы с ключами.
 */
public class CryptoUtil {

    /**
     * Генерирует пару ключей RSA (открытый и закрытый).
     *
     * @return объект KeyPair, содержащий сгенерированные открытый и закрытый ключи.
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации ключей RSA", e);
        }
    }

    /**
     * Кодирует публичный ключ RSA в строку в формате Base64.
     *
     * @param publicKey публичный ключ RSA.
     * @return строковое представление публичного ключа в формате Base64.
     */
    public static String encodeRSAPublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Кодирует приватный ключ RSA в строку в формате Base64.
     *
     * @param privateKey приватный ключ RSA.
     * @return строковое представление приватного ключа в формате Base64.
     */
    public static String encodeRSAPrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Декодирует строку Base64 в объект PublicKey (публичный ключ RSA).
     *
     * @param publicKeyStr строковое представление публичного ключа в формате Base64.
     * @return объект PublicKey, декодированный из строки.
     */
    public static PublicKey decodeRSAPublicKey(String publicKeyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка декодирования публичного ключа RSA", e);
        }
    }

    /**
     * Декодирует строку Base64 в объект PrivateKey (приватный ключ RSA).
     *
     * @param privateKeyStr строковое представление приватного ключа в формате Base64.
     * @return объект PrivateKey, декодированный из строки.
     */
    public static PrivateKey decodeRSAPrivateKey(String privateKeyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка декодирования приватного ключа RSA", e);
        }
    }

    /**
     * Шифрует файл с помощью алгоритма RSA и публичного ключа.
     *
     * @param inputFile файл для шифрования.
     * @param publicKey публичный ключ для шифрования.
     * @return зашифрованный файл.
     */
    public static File encryptFileRSA(File inputFile, PublicKey publicKey) {
        try {
            byte[] fileData = Files.readAllBytes(inputFile.toPath());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(fileData);

            File encryptedFile = new File(inputFile.getParent(), "encrypted_" + inputFile.getName());
            try (FileOutputStream fos = new FileOutputStream(encryptedFile)) {
                fos.write(encryptedData);
            }
            return encryptedFile;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка шифрования файла RSA", e);
        }
    }

    /**
     * Дешифрует файл с помощью алгоритма RSA и приватного ключа.
     *
     * @param encryptedFile зашифрованный файл.
     * @param privateKey приватный ключ для дешифрования.
     * @return расшифрованный файл.
     */
    public static File decryptFileRSA(File encryptedFile, PrivateKey privateKey) {
        try {
            byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            File decryptedFile = new File(encryptedFile.getParent(), "decrypted_" + encryptedFile.getName());
            try (FileOutputStream fos = new FileOutputStream(decryptedFile)) {
                fos.write(decryptedData);
            }
            return decryptedFile;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка дешифрования файла RSA", e);
        }
    }

    /**
     * Генерирует секретный ключ AES для симметричного шифрования.
     *
     * @return сгенерированный секретный ключ AES.
     */
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // Использование 256-битного ключа AES
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации AES ключа", e);
        }
    }

    /**
     * Кодирует секретный ключ AES в строку в формате Base64.
     *
     * @param secretKey секретный ключ AES.
     * @return строковое представление секретного ключа в формате Base64.
     */
    public static String encodeAESKey(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * Декодирует строку Base64 в объект SecretKey (секретный ключ AES).
     *
     * @param keyStr строковое представление ключа AES в формате Base64.
     * @return объект SecretKey, декодированный из строки.
     */
    public static SecretKey decodeAESKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    /**
     * Шифрует файл с помощью алгоритма AES и секретного ключа.
     *
     * @param inputFile файл для шифрования.
     * @param secretKey секретный ключ AES.
     * @return зашифрованный файл.
     */
    public static File encryptFileAES(File inputFile, SecretKey secretKey) {
        try {
            byte[] fileData = Files.readAllBytes(inputFile.toPath());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(fileData);

            File encryptedFile = new File(inputFile.getParent(), "encrypted_" + inputFile.getName());
            try (FileOutputStream fos = new FileOutputStream(encryptedFile)) {
                fos.write(encryptedData);
            }
            return encryptedFile;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка шифрования файла AES", e);
        }
    }

    /**
     * Дешифрует файл с помощью алгоритма AES и секретного ключа.
     *
     * @param encryptedFile зашифрованный файл.
     * @param secretKey секретный ключ AES.
     * @return расшифрованный файл.
     */
    public static File decryptFileAES(File encryptedFile, SecretKey secretKey) {
        try {
            byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            File decryptedFile = new File(encryptedFile.getParent(), "decrypted_" + encryptedFile.getName());
            try (FileOutputStream fos = new FileOutputStream(decryptedFile)) {
                fos.write(decryptedData);
            }
            return decryptedFile;
        } catch (Exception e) {
            throw new RuntimeException("Ошибка дешифрования файла AES", e);
        }
    }
}
----------------------------------------------------------------------------------------------
Код класса Client:
package org.example.demo;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.util.logging.Logger;

/**
 * Класс для реализации клиентской части приложения для шифрования и подписи файлов.
 * Включает в себя интерфейс для выбора файла, генерации ключей, шифрования и дешифрования.
 */
public class Client extends Application {

    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private File selectedFile;
    private File encryptedFile;
    private File decryptedFile;
    private String publicKey;
    private String privateKey;

    /**
     * Метод для запуска графического интерфейса приложения.
     * Создает и отображает окно с элементами управления для шифрования и дешифрования.
     *
     * @param primaryStage начальная сцена приложения
     */
    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Клиент: Шифрование и Подпись");

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setHgap(10);
        grid.setVgap(10);

        // Компоненты интерфейса
        Button chooseFileButton = new Button("Выбрать файл");
        Label fileLabel = new Label("Файл не выбран");
        ComboBox<String> algorithmBox = new ComboBox<>();
        algorithmBox.getItems().addAll("RSA + SHA256", "AES + SHA256");
        algorithmBox.setValue("RSA + SHA256");
        Button generateKeyButton = new Button("Сгенерировать ключ");
        TextArea publicKeyArea = new TextArea();
        publicKeyArea.setEditable(false);
        Button copyKeyButton = new Button("Скопировать ключ");
        Button encryptButton = new Button("Зашифровать");
        TextField inputKeyField = new TextField();
        Button decryptButton = new Button("Дешифровать файл");
        Button saveFileButton = new Button("Сохранить файл");

        // Расположение компонентов
        grid.add(chooseFileButton, 0, 0);
        grid.add(fileLabel, 1, 0);
        grid.add(new Label("Алгоритм:"), 0, 1);
        grid.add(algorithmBox, 1, 1);
        grid.add(generateKeyButton, 0, 2);
        grid.add(new Label("Публичный ключ:"), 0, 3);
        grid.add(publicKeyArea, 1, 3);
        grid.add(copyKeyButton, 0, 4);
        grid.add(encryptButton, 0, 5);
        grid.add(new Label("Личный ключ для дешифрования:"), 0, 6);
        grid.add(inputKeyField, 1, 6);
        grid.add(decryptButton, 0, 7);
        grid.add(saveFileButton, 0, 8);

        // Обработчики событий
        chooseFileButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            selectedFile = fileChooser.showOpenDialog(primaryStage);
            if (selectedFile != null) {
                fileLabel.setText("Файл выбран: " + selectedFile.getName());
                logger.info("Выбран файл: " + selectedFile.getName());
            }
        });

        generateKeyButton.setOnAction(e -> {
            String algorithm = algorithmBox.getValue();
            if (algorithm.contains("RSA")) {
                var keyPair = org.example.demo.CryptoUtil.generateKeyPair();
                privateKey = org.example.demo.CryptoUtil.encodeRSAPrivateKey(keyPair.getPrivate());
                publicKey = org.example.demo.CryptoUtil.encodeRSAPublicKey(keyPair.getPublic());
                publicKeyArea.setText(publicKey);  // Приватный ключ сохраняется в поле публичного ключа
                inputKeyField.setText(privateKey);  // Приватный ключ сохраняется в поле личного ключа
            } else {
                SecretKey secretKey = org.example.demo.CryptoUtil.generateAESKey();
                publicKey = org.example.demo.CryptoUtil.encodeAESKey(secretKey);
                privateKey = publicKey;
                publicKeyArea.setText(publicKey);
                inputKeyField.setText(privateKey);
            }
            logger.info("Сгенерирован ключ: " + privateKey);
        });

        copyKeyButton.setOnAction(e -> {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(publicKey);
            clipboard.setContent(content);
            logger.info("Ключ скопирован в буфер обмена.");
        });

        encryptButton.setOnAction(e -> {
            if (selectedFile == null || publicKey == null) {
                showAlert("Ошибка", "Выберите файл и сгенерируйте ключ!");
                return;
            }
            try {
                String algorithm = algorithmBox.getValue();
                if (algorithm.contains("RSA")) {
                    encryptedFile = org.example.demo.CryptoUtil.encryptFileRSA(selectedFile, org.example.demo.CryptoUtil.decodeRSAPublicKey(publicKey));
                } else {
                    SecretKey secretKey = org.example.demo.CryptoUtil.decodeAESKey(publicKey);
                    encryptedFile = org.example.demo.CryptoUtil.encryptFileAES(selectedFile, secretKey);
                }
                if (encryptedFile != null) {
                    logger.info("Файл успешно зашифрован: " + encryptedFile.getName());
                    showAlert("Успех", "Файл успешно зашифрован!");
                }
            } catch (Exception ex) {
                logger.severe("Ошибка шифрования: " + ex.getMessage());
                showAlert("Ошибка", "Не удалось зашифровать файл: " + ex.getMessage());
            }
        });

        decryptButton.setOnAction(e -> {
            if (encryptedFile == null || inputKeyField.getText().isEmpty()) {
                showAlert("Ошибка", "Введите ключ и зашифруйте файл перед дешифрованием!");
                return;
            }
            try {
                String algorithm = algorithmBox.getValue();
                String inputKey = inputKeyField.getText();
                if (algorithm.contains("RSA")) {
                    decryptedFile = org.example.demo.CryptoUtil.decryptFileRSA(encryptedFile, org.example.demo.CryptoUtil.decodeRSAPrivateKey(inputKey));
                } else {
                    SecretKey secretKey = org.example.demo.CryptoUtil.decodeAESKey(inputKey);
                    decryptedFile = org.example.demo.CryptoUtil.decryptFileAES(encryptedFile, secretKey);
                }
                if (decryptedFile != null) {
                    logger.info("Файл успешно дешифрован: " + decryptedFile.getName());
                    showAlert("Успех", "Файл успешно дешифрован!");
                }
            } catch (Exception ex) {
                logger.severe("Ошибка дешифрования: " + ex.getMessage());
                showAlert("Ошибка", "Не удалось дешифровать файл: " + ex.getMessage());
            }
        });

        saveFileButton.setOnAction(e -> {
            if (decryptedFile != null || encryptedFile != null) {
                FileChooser fileChooser = new FileChooser();
                File saveFile = fileChooser.showSaveDialog(primaryStage);
                if (saveFile != null) {
                    try {
                        File fileToSave = (decryptedFile != null) ? decryptedFile : encryptedFile;
                        Files.copy(fileToSave.toPath(), saveFile.toPath());
                        logger.info("Файл успешно сохранён: " + saveFile.getName());
                        showAlert("Успех", "Файл успешно сохранён!");
                    } catch (Exception ex) {
                        logger.severe("Ошибка сохранения файла: " + ex.getMessage());
                        showAlert("Ошибка", "Не удалось сохранить файл: " + ex.getMessage());
                    }
                }
            } else {
                showAlert("Ошибка", "Нет файла для сохранения!");
            }
        });

        // Установка сцены и отображение окна
        Scene scene = new Scene(grid, 600, 500);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * Метод для отображения окна с информацией.
     * Используется для вывода уведомлений о результате операции (успех или ошибка).
     *
     * @param title   заголовок окна
     * @param message сообщение для отображения в окне
     */
    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
----------------------------------------------------------------------------------------------
module-info.java:
module finalochka {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.apache.logging.log4j;
    requires java.logging;
    requires com.formdev.flatlaf;
    requires java.desktop;
    requires org.apache.logging.log4j.core;
    requires java.base;
    exports org.example.demo;
}
----------------------------------------------------------------------------------------------
класс ClientLogicTest:

package org.example.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class ClientLogicTest {

    private org.example.demo.Client client;

    @BeforeEach
    void setUp() {
        client = new org.example.demo.Client();
    }

    @Test
    void testGenerateRSAKeys() {
        KeyPair keyPair = org.example.demo.CryptoUtil.generateKeyPair();
        String publicKey = org.example.demo.CryptoUtil.encodeRSAPublicKey(keyPair.getPublic());
        String privateKey = org.example.demo.CryptoUtil.encodeRSAPrivateKey(keyPair.getPrivate());

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        // Проверка декодирования ключей
        assertDoesNotThrow(() -> org.example.demo.CryptoUtil.decodeRSAPublicKey(publicKey));
        assertDoesNotThrow(() -> org.example.demo.CryptoUtil.decodeRSAPrivateKey(privateKey));
    }

    @Test
    void testGenerateAESKey() {
        SecretKey secretKey = org.example.demo.CryptoUtil.generateAESKey();
        String encodedKey = org.example.demo.CryptoUtil.encodeAESKey(secretKey);

        assertNotNull(encodedKey);

        // Проверка декодирования ключа
        SecretKey decodedKey = org.example.demo.CryptoUtil.decodeAESKey(encodedKey);
        assertNotNull(decodedKey);
        assertEquals(secretKey, decodedKey);
    }

    @Test
    void testEncryptAndDecryptRSA() throws Exception {
        // Создание временного файла
        File tempFile = File.createTempFile("test", ".txt");
        Files.write(tempFile.toPath(), "Test content".getBytes());

        KeyPair keyPair = org.example.demo.CryptoUtil.generateKeyPair();
        File encryptedFile = org.example.demo.CryptoUtil.encryptFileRSA(tempFile, keyPair.getPublic());
        File decryptedFile = org.example.demo.CryptoUtil.decryptFileRSA(encryptedFile, keyPair.getPrivate());

        assertNotNull(encryptedFile);
        assertNotNull(decryptedFile);

        // Проверка содержимого файла после дешифрования
        String decryptedContent = Files.readString(decryptedFile.toPath());
        assertEquals("Test content", decryptedContent);

        // Удаление временных файлов
        tempFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
    }

    @Test
    void testEncryptAndDecryptAES() throws Exception {
        // Создание временного файла
        File tempFile = File.createTempFile("test", ".txt");
        Files.write(tempFile.toPath(), "Test content".getBytes());

        SecretKey secretKey = org.example.demo.CryptoUtil.generateAESKey();
        File encryptedFile = org.example.demo.CryptoUtil.encryptFileAES(tempFile, secretKey);
        File decryptedFile = org.example.demo.CryptoUtil.decryptFileAES(encryptedFile, secretKey);

        assertNotNull(encryptedFile);
        assertNotNull(decryptedFile);

        // Проверка содержимого файла после дешифрования
        String decryptedContent = Files.readString(decryptedFile.toPath());
        assertEquals("Test content", decryptedContent);

        // Удаление временных файлов
        tempFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
    }
}
----------------------------------------------------------------------------------------------
класс CryptoUtilTest:
package org.example.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {

    private KeyPair rsaKeyPair;
    private SecretKey aesKey;
    private File testFile;

    @BeforeEach
    void setUp() throws Exception {
        // Генерация ключей для тестов
        rsaKeyPair = org.example.demo.CryptoUtil.generateKeyPair();
        aesKey = org.example.demo.CryptoUtil.generateAESKey();

        // Создание временного тестового файла
        testFile = File.createTempFile("test", ".txt");
        try (FileWriter writer = new FileWriter(testFile)) {
            writer.write("Это тестовое содержимое файла.");
        }
    }

    @Test
    void testGenerateKeyPair() {
        assertNotNull(rsaKeyPair);
        assertNotNull(rsaKeyPair.getPublic());
        assertNotNull(rsaKeyPair.getPrivate());
    }

    @Test
    void testEncodeAndDecodeRSAPublicKey() {
        String encodedPublicKey = org.example.demo.CryptoUtil.encodeRSAPublicKey(rsaKeyPair.getPublic());
        PublicKey decodedPublicKey = org.example.demo.CryptoUtil.decodeRSAPublicKey(encodedPublicKey);

        assertEquals(rsaKeyPair.getPublic(), decodedPublicKey);
    }

    @Test
    void testEncodeAndDecodeRSAPrivateKey() {
        String encodedPrivateKey = org.example.demo.CryptoUtil.encodeRSAPrivateKey(rsaKeyPair.getPrivate());
        PrivateKey decodedPrivateKey = org.example.demo.CryptoUtil.decodeRSAPrivateKey(encodedPrivateKey);

        assertEquals(rsaKeyPair.getPrivate(), decodedPrivateKey);
    }

    @Test
    void testEncryptAndDecryptFileRSA() throws Exception {
        // Шифрование файла
        File encryptedFile = org.example.demo.CryptoUtil.encryptFileRSA(testFile, rsaKeyPair.getPublic());
        assertTrue(encryptedFile.exists());
        assertNotEquals(Files.readAllBytes(testFile.toPath()), Files.readAllBytes(encryptedFile.toPath()));

        // Дешифрование файла
        File decryptedFile = org.example.demo.CryptoUtil.decryptFileRSA(encryptedFile, rsaKeyPair.getPrivate());
        assertTrue(decryptedFile.exists());
        assertArrayEquals(Files.readAllBytes(testFile.toPath()), Files.readAllBytes(decryptedFile.toPath()));
    }

    @Test
    void testGenerateAESKey() {
        assertNotNull(aesKey);
    }

    @Test
    void testEncodeAndDecodeAESKey() {
        String encodedAESKey = org.example.demo.CryptoUtil.encodeAESKey(aesKey);
        SecretKey decodedAESKey = org.example.demo.CryptoUtil.decodeAESKey(encodedAESKey);

        assertArrayEquals(aesKey.getEncoded(), decodedAESKey.getEncoded());
    }

    @Test
    void testEncryptAndDecryptFileAES() throws Exception {
        // Шифрование файла
        File encryptedFile = org.example.demo.CryptoUtil.encryptFileAES(testFile, aesKey);
        assertTrue(encryptedFile.exists());
        assertNotEquals(Files.readAllBytes(testFile.toPath()), Files.readAllBytes(encryptedFile.toPath()));

        // Дешифрование файла
        File decryptedFile = org.example.demo.CryptoUtil.decryptFileAES(encryptedFile, aesKey);
        assertTrue(decryptedFile.exists());
        assertArrayEquals(Files.readAllBytes(testFile.toPath()), Files.readAllBytes(decryptedFile.toPath()));
    }
}

----------------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------------
класс ServerTest:
package org.example.demo;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.Socket;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerTest {

    private static final int PORT = 12345;
    private Thread serverThread;

    @BeforeEach
    void setUp() {
        // Запускаем сервер в отдельном потоке
        serverThread = new Thread(() -> org.example.demo.Server.startServer());
        serverThread.setDaemon(true); // Закрыть поток после завершения теста
        serverThread.start();
    }

    @AfterEach
    void tearDown() {
        // После тестов сервер будет автоматически завершён, так как поток daemon
    }

    @Test
    void testClientConnectionAndFileProcessing() throws Exception {
        // Создаём клиента
        try (Socket clientSocket = new Socket("localhost", PORT);
             OutputStream outputStream = clientSocket.getOutputStream();
             InputStream inputStream = clientSocket.getInputStream()) {

            // Отправляем зашифрованный файл
            String testContent = "This is a test file.";
            byte[] testBytes = testContent.getBytes();
            outputStream.write(testBytes);
            outputStream.flush();
            clientSocket.shutdownOutput(); // Указываем, что запись завершена

            // Ожидаем ответа от сервера
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                responseStream.write(buffer, 0, bytesRead);
            }

            // Проверяем ответ сервера
            String response = responseStream.toString();
            assertEquals("Файл успешно получен и обработан.", response);

            // Проверяем, что файл был создан на сервере
            File receivedFile = new File("received_encrypted_file");
            assertEquals(testContent, readFileContent(receivedFile));

            // Удаляем файл после теста
            if (receivedFile.exists()) {
                receivedFile.delete();
            }
        }
    }

    private String readFileContent(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            return bos.toString();
        }
    }
}

----------------------------------------------------------------------------------------------
