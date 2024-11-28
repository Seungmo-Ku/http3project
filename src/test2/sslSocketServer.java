package test2;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.StringTokenizer;

public class sslSocketServer {

    private static int assignedSourceID = 0;
    private static int serverStreamID = 0;
    public static void main(String[] args) throws Exception {
        // 키 저장소 설정
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("mykeystore.jks"), "changeit".toCharArray());

        // 키 매니저 팩토리 생성
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        // SSLContext 생성
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), null, null);

        // SSLServerSocketFactory 생성
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(7777);

        System.out.println("Server started. Waiting for connections...");

        while (true) {
            SSLSocket socket = (SSLSocket) serverSocket.accept();
            System.out.println("Client connected.");
            // 클라이언트와의 통신 처리
            handleClient(socket);
        }
    }

    private static void handleClient(SSLSocket socket) {

        int headerForm;
        int fixedBit;
        int longPacketType;
        int typeSpecificBits;
        int versionID;
        int destinationID;
        int sourceID = 0;
        int streamNum = 0;
        String payload;
        String method;

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String headerFirstLine;
            while((headerFirstLine = in.readLine()) != null) {
                System.out.println(headerFirstLine);
                if(getInt(headerFirstLine.charAt(1)) != 1) {
                    System.out.println("Wrong header");
                }
                headerForm = getInt(headerFirstLine.charAt(0));
                if (headerForm == 1) { //long header는 prior to the connection establishment
                    System.out.println("Long Header");
                    fixedBit = getInt(headerFirstLine.charAt(1));
                    longPacketType = getInt(headerFirstLine.charAt(3)); //0x00, 0x01, 0x02, 0x03
                    typeSpecificBits = Integer.parseInt(headerFirstLine.substring(4, 8), 16);

                    System.out.println("HeaderForm: " + headerForm);
                    System.out.println("FixedBit: " + fixedBit);
                    System.out.println("LongPacketType: " + longPacketType);
                    System.out.println("TypeSpecificBits: " + typeSpecificBits);

                    //version
                    versionID = Integer.parseInt(headerFirstLine.substring(8, 16), 16);
                    System.out.println("VersionID: " + versionID);
                    //destination
                    destinationID = Integer.parseInt(headerFirstLine.substring(16, 24), 16);
                    sourceID = Integer.parseInt(headerFirstLine.substring(24, 32), 16);
                    System.out.println("DestinationID: " + destinationID);
                    System.out.println("SourceID: " + sourceID);
                    if(sourceID != 65535 && sourceID > assignedSourceID) {
                        throw new IOException();
                    }
                    if (sourceID == 65535) { //assign sourceID
                        out.println(createQuicShortHeader(++assignedSourceID, "00000REJ"));
                        System.out.println("sent reject");
                    } else {
                        out.println(createQuicShortHeader(sourceID, "00000HLO"));
                        System.out.println("Sent hello");
                    }
                } else { //short header
                    System.out.println("Short Header");

                    streamNum = Integer.parseInt(removeAppString(headerFirstLine.substring(24, 32)));
                    int i = streamNum;
                    System.out.println("StreamNum: " + streamNum);
                    String outString = "";
                    while (i > 0) {
                        String stream = in.readLine();
                        //00000110
                        int unidirectional = Integer.parseInt(stream.substring(6, 7));

                        /*
                        Stream Frame : Type(8)(생략), Stream ID (8), Offset(생략), Stream Data Length(일단 생략), Stream Data (data length)
                        000001
                        스트림 id의 최하위 비트: 1 --> 클라이언트, 0 --> 서버
                        두번째 하위 비트 : 1 --> 단방향, 0 --> 양방향
                        양방향이면 한 쪽에서 스트림을 보냈을 때 같은 stream id로 교신 가능
                        */

                        String methodLine = in.readLine();
                        System.out.println("Stream: " + stream);
                        System.out.println("Method Line: " + methodLine);
                        payload = methodLine.substring(18, 21);
                        System.out.println("Method: " + payload);
                        if (payload.equals("GET")) {
                            //method = in.readLine(); // HEADERS {:method: GET:scheme: https:authority: localhost:path: /index.html}
                            StringTokenizer tokens = new StringTokenizer(methodLine, ":");
                            String path = null;
                            while (tokens.hasMoreTokens()) {
                                if (tokens.nextToken().equals("path")) {
                                    path = tokens.nextToken();
                                }
                            }
                            if (path == null) {
                                throw new IOException();
                            }
                            path = path.substring(1, path.length() - 1);


                            // Prepend a "." so that file request is within the current directory.
                            path = "." + path;

                            System.out.println("Path:" + path);

                            // Open the requested file.
                            FileInputStream fis = null;
                            boolean fileExists = true;
                            try {
                                fis = new FileInputStream(path);
                            } catch (FileNotFoundException e) {
                                fileExists = false;
                            }

                            String statusLine = null;
                            String contentTypeLine = null;
                            String contentLengthLine = null;
                            String entityBody = null;

                            if (fileExists) {
                                statusLine = ":status: 200";
                                contentTypeLine = "content-type: " + contentType(path);
                                contentLengthLine = "content-length: " + getFileSizeBytes(path);
                            } else {
                                statusLine = ":status: 404";
                                contentTypeLine = "content-type: text/html";
                                entityBody = "<HTML><HEAD><TITLE>Not Found</TITLE></HEAD><BODY>Not Found</BODY></HTML>";
                            }

                            if (fileExists) {
                                int writeByte;
                                entityBody = "";
                                while ((writeByte = fis.read()) != -1) {
                                    entityBody += (char) writeByte;
                                }
                            }


                            outString += createFrameHeader(stream, statusLine + '\n' + contentTypeLine + '\n'
                                    + contentLengthLine + '\n' + entityBody + '\n');

                        }
                        i--;
                        System.out.println("i : " + i);
                }
                    outString = createQuicShortHeader(sourceID, streamNum + "") + '\n' + outString;
                    System.out.println("outString : " + outString);
                    out.println(outString);

                }

            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int getInt(char c) {
        return Character.getNumericValue(c);
    }

    private static String createQuicShortHeader(int destinationID, String payload) {
        String headerStr = "01100000" /*header form 1, fixed bit 1, spin bits 2, reserved 2 key phase 1 packet number length 2*/
                + makeAppString(destinationID) /*Destination ID*/
                + "00000005" /*Packet number*/ + makeAppString(payload) /*protected payload*/;
        return headerStr;
    }

    private static String createFrameHeader(boolean unidirectional, String payload) {
        String frameHeader = "";
        String streamIDstring = "";
        streamIDstring += ++serverStreamID;
        if(unidirectional) {
            streamIDstring += 0;
        }else {
            streamIDstring += 1;
        }
        streamIDstring += 1; // client
        frameHeader += makeAppString(streamIDstring) + '\n';
        frameHeader += payload;
        //System.out.println("Frame Header : " + frameHeader);
        return frameHeader;
    }
    private static String createFrameHeader(String existingStreamID, String payload) {
        String frameHeader = "";
        frameHeader += existingStreamID + '\n';
        frameHeader += payload;
        //System.out.println("Frame Header : " + frameHeader);
        return frameHeader;
    }
    private static String makeAppString(int data) {
        String appString = "";
        String dataString = data + "";
        for(int i = 1; i < 9 - dataString.length(); i++) {
            appString += "0";
        }
        appString += dataString;
        return appString;
    }

    private static String makeAppString(String dataString) {
        String appString = "";
        for(int i = 1; i < 9 - dataString.length(); i++) {
            appString += "0";
        }
        appString += dataString;
        return appString;
    }
    private static String removeAppString(String payload) {
        String appString = "";
        for(int i = 0; i < 8; i++) {
            if(payload.charAt(i) != '0') {appString += payload.charAt(i);}
        }
        return appString;
    }
    private static void sendBytes(FileInputStream fis,
                                  OutputStream os) throws Exception {
        // Construct a 1K buffer to hold bytes on their way to the socket.
        byte[] buffer = new byte[1024];
        int bytes = 0;

        // Copy requested file into the socket's output stream.
        while ((bytes = fis.read(buffer)) != -1) {
            os.write(buffer, 0, bytes);
        }
    }
    private static String contentType(String fileName) {
        if(fileName.endsWith(".htm") || fileName.endsWith(".html")) {
            return "text/html";
        }
/**
 * create an HTTP response message consisting of the requested file preceded by header lines
 * Now, you are just handling text/html, is there any more context-types? Find and make codes for it.
 */
        if(fileName.endsWith(".ram") || fileName.endsWith(".ra")) {
            return "audio/x-pn-realaudio";
        }
        if(fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        return "application/octet-stream" ;
    }

    /**
     * Get the File name, and through the file name, get the size of the file.
     *.@param fileName
     */
    private static long getFileSizeBytes(String fileName) throws IOException {
        File file = new File(fileName);
        return file.length();
    }

}