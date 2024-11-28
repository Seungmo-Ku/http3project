package test2;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.Scanner;

public class sslSocketClient {

    private static int sourceID = -1;
    private static int clientStreamID = 0;
    private static String createQuicLongHeader() {
        String sourceText;
        if(sourceID == -1) {
            sourceText = "0000ffff";
        }else {
            sourceText = "0000000" + sourceID;
        }

        String headerStr = "11100000" /*header form 1, fixed bit 1, long packet type 2, type specific bits 4*/
                + "000000a2" /*version ID*/     + "00000000" /*Destination ID*/
                + sourceText /*Source ID*/;
        return headerStr;
    }

    private static String createQuicShortHeader(String payload) {
        String headerStr = "01100000" /*header form 1, fixed bit 1, spin bits 2, reserved 2 key phase 1 packet number length 2*/
                + "00000000" /*Destination ID*/
                + "00000005" /*Packet number*/ + makeAppString(payload) /*protected payload*/;
        return headerStr;
    }
    private static String createGetMethod(String fileName) {
        String getMethod = "HEADERS {" + ":method: GET" +
                ":scheme: https" +
                ":authority: localhost" +
                ":path: /"+fileName +
                "}";

        return getMethod;
    }
    private static String createFrameHeader(boolean unidirectional, String payload) {
        String frameHeader = "";
        String streamIDstring = "";
        streamIDstring += ++clientStreamID;
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
    /*
    Stream Frame : Type(8)(생략), Stream ID (8), Offset(생략), Stream Data Length(일단 생략), Stream Data (data length)
    000001
    스트림 id의 최하위 비트: 1 --> 클라이언트, 0 --> 서버
    두번째 하위 비트 : 1 --> 단방향, 0 --> 양방향
    양방향이면 한 쪽에서 스트림을 보냈을 때 같은 stream id로 교신 가능
     */

    public static void main(String[] args) throws Exception {
        System.out.println(createFrameHeader(true, "aaa"));
        // 키 저장소 설정 (선택적)
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("mykeystore.jks"), "changeit".toCharArray());

        // 신뢰할 수 있는 인증서 설정
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        // SSLContext 생성
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, tmf.getTrustManagers(), null);

        // SSLSocketFactory 생성
        SSLSocketFactory sf = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) sf.createSocket("localhost", 7777);

        // 데이터 전송
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        if(args.length != 0)
                sourceID = Integer.parseInt(args[0]);




        // 메시지 전송
        out.println(createQuicLongHeader());

        String headerFirstLine = in.readLine();

        System.out.println(headerFirstLine);

        if(getInt(headerFirstLine.charAt(1)) != 1) {
            System.out.println("Wrong header");
        }

        sourceID = Integer.parseInt(headerFirstLine.substring(8, 16), 16);
        System.out.println("SourceID: " + sourceID);
        String payload = removeAppString(headerFirstLine.substring(24, 32));
        System.out.println("Payload: " + payload);

        while(!payload.equals("HLO")) {
            out.println(createQuicLongHeader());
            String response = in.readLine();
            payload = removeAppString(response.substring(24, 32));
            System.out.println(response);
            sourceID = Integer.parseInt(headerFirstLine.substring(8, 16), 16);
            System.out.println("SourceID: " + sourceID);
            System.out.println("Payload: " + payload);
        }

        System.out.println("Completed QUIC Handshake");
        //quic handshake 완료

        while(true) {

            System.out.print("\n0 : 프로그램 종료, 1 : GET\n응답 : ");

            Scanner scanner = new Scanner(System.in);
            int j = scanner.nextInt();

            if(j == 0) break;
            else {
                System.out.print("Stream의 수\n응답 : ");

                int numOfStream = scanner.nextInt();
                out.println(createQuicShortHeader(numOfStream + ""));
                scanner.nextLine();
                int i = numOfStream;
                while(i > 0) {
                    System.out.print("File name for stream " + (numOfStream - i + 1) + " : ");
                    out.println(createFrameHeader(true, createGetMethod(scanner.nextLine())));
                    i--;
                }
                System.out.println("Responses Arrived :: ");
                //in.readLine();
                String quicHeaderLine;
                int streamNum;
                while((quicHeaderLine = in.readLine()).length() == 0)
                    quicHeaderLine = in.readLine();
                System.out.println("Quic header line: " + quicHeaderLine);
                streamNum = Integer.parseInt(removeAppString(quicHeaderLine.substring(24, 32)));
                i = streamNum;
                while(i > 0) {
                    String streamLine = null;
                    String statusLine = null;
                    String contentTypeLine = null;
                    String contentLengthLine = null;
                    String entityBody = null;

                    streamLine = in.readLine();
                    statusLine = in.readLine();
                    System.out.println("\n\n\n");
                    System.out.println("Stream "+ (streamNum - i + 1) +" arrived: " + streamLine);
                    System.out.println("Stream number : " + Integer.parseInt(streamLine.substring(0, 6)));

                    contentTypeLine = in.readLine();
                    contentLengthLine = in.readLine();
                    entityBody = in.readLine();

                    System.out.println(statusLine);
                    System.out.println(contentTypeLine);
                    System.out.println(contentLengthLine);
                    System.out.println(entityBody);
                    i --;
                }
                in.readLine();


            }
        }
        // 연결 종료
        socket.close();
    }

    private static int getInt(char c) {
        return Character.getNumericValue(c);
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

}
