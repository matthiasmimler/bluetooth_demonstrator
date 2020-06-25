#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <map>

#include <winsock2.h>
#include <ws2bth.h>
#include <BluetoothAPIs.h>
#include <atlstr.h>

struct bt_device_info
{
    explicit bt_device_info(const BLUETOOTH_DEVICE_INFO_STRUCT& i) : info(i) {}

    BLUETOOTH_DEVICE_INFO_STRUCT info;
};

std::map<std::size_t, bt_device_info> scan_bt_devices()
{
    BLUETOOTH_DEVICE_SEARCH_PARAMS search_params =
    {
        sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS), // dwSize (size)
        TRUE, // fReturnAuthenticated (return authenticated devices)
        FALSE, // fReturnRemembered (return remembered devices)
        TRUE, // fReturnUnknown (return unknown devices)
        TRUE, // fReturnConnected (return connected devices)
        TRUE, // fIssueInquiry (issue new inquiry)
        4, // cTimeoutMultiplier (number of increments of 1.28 sec, maximum value is 48)
        NULL // 
    };

    BLUETOOTH_DEVICE_INFO_STRUCT device_info;
    device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO_STRUCT);

    auto devices = std::map<std::size_t, bt_device_info>{};
    auto find_handle =  BluetoothFindFirstDevice(&search_params, &device_info);
    int count = 0;

    if (find_handle)
    {
        do
        {
            devices.emplace(++count, device_info);
        } while (BluetoothFindNextDevice(find_handle, &device_info));
    }

    if (!BluetoothFindDeviceClose(find_handle))
    {
        throw std::exception{ "BluetoothFindDeviceClose() failed" };
    }

    return devices;
}

// Authentication callback
BOOL WINAPI BluetoothAuthCallback(LPVOID param, PBLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS auth_callback_params)
{
    DWORD result = ERROR_SUCCESS;

    fprintf(stderr, "BluetoothAuthCallback 0x%xn", static_cast<unsigned int>(auth_callback_params->deviceInfo.Address.ullLong));
    BLUETOOTH_AUTHENTICATE_RESPONSE auth_response;
    auth_response.authMethod = auth_callback_params->authenticationMethod;
    fprintf(stderr, "Authmethod %dn", auth_response.authMethod);
    fprintf(stderr, "I/O : %dn", auth_callback_params->ioCapability);

    // With BLUETOOTH_AUTHENTICATION_METHOD_NUMERIC_COMPARISON connection working
    if (auth_response.authMethod == BLUETOOTH_AUTHENTICATION_METHOD_NUMERIC_COMPARISON)
    {
        fprintf(stderr, "Numeric Comparison supportedn");

        auth_response.bthAddressRemote = auth_callback_params->deviceInfo.Address;
        auth_response.negativeResponse = FALSE;

        // Respond with numerical value for Just Works pairing
        auth_response.numericCompInfo.NumericValue = 1;

        // Send authentication response to authenticate device
        result = BluetoothSendAuthenticationResponseEx(NULL, &auth_response);
    }
    // With BLUETOOTH_AUTHENTICATION_METHOD_LEGACY connection not working
    else if (auth_response.authMethod == BLUETOOTH_AUTHENTICATION_METHOD_LEGACY)
    {
        auth_response.bthAddressRemote = auth_callback_params->deviceInfo.Address;
        auth_response.negativeResponse = FALSE;

        //Pin
        UCHAR pin[] = "0000";
        std::copy(pin, pin + sizeof(pin), auth_response.pinInfo.pin);
        auth_response.pinInfo.pinLength = sizeof(pin) - 1;;

        // Respond with numerical value for Just Works pairing
        //AuthRes.numericCompInfo.NumericValue = 1;

        fprintf(stderr, "Authentication via a PINn");
        result = BluetoothSendAuthenticationResponseEx(NULL, &auth_response);
    }

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "BluetoothSendAuthenticationResponseEx ret %dn", result);
    }
    else
    {
        fprintf(stderr, "BluetoothAuthCallback finish");
    }

    return 1; // This value is ignored
}

void pair(bt_device_info device_info)
{
    auto device = device_info.info;

    std::wstring ws = device.szName;
    std::cout << "Pairing device " << CW2A(device.szName) << std::endl;

    // register callback
    std::cout << "Registering callback" << std::endl;
    HBLUETOOTH_AUTHENTICATION_REGISTRATION callback_handle = 0;
    auto result = BluetoothRegisterForAuthenticationEx(NULL, &callback_handle, (PFN_AUTHENTICATION_CALLBACK_EX)&BluetoothAuthCallback, NULL);

    if (result != ERROR_SUCCESS)
    {
        BluetoothUnregisterAuthentication(callback_handle);
        return;
    }

    // authenticate
    result = BluetoothAuthenticateDeviceEx(NULL, NULL, &device, NULL, MITMProtectionNotRequired);

    switch (result)
    {
    case ERROR_SUCCESS:
        std::cout << "pair device success" << std::endl;
        break;

    case ERROR_CANCELLED:
        std::cout << "pair device failed, user cancelled" << std::endl;
        break;

    case ERROR_INVALID_PARAMETER:
        std::cout << "pair device failed, invalid parameter" << std::endl;
        break;

    case ERROR_NO_MORE_ITEMS:
        std::cout << "pair device failed, device appears paired already" << std::endl;
        break;

    default:
        std::cout << "pair device failed, unknown error, code " << (unsigned int)result << std::endl;
        break;
    }

    BluetoothUnregisterAuthentication(callback_handle);

    HANDLE btHeadset;
    //todo: 
    // 1. we are just getting the first radio. Need to check whetehr it is right
    // 2. We after the BluetoothSetServiceState, it only sets the "Outgoing COM", not "Incoming"
    BLUETOOTH_FIND_RADIO_PARAMS rfind = { sizeof(rfind) };
    BluetoothFindFirstRadio(&rfind, &btHeadset);

    GUID id = SerialPortServiceClass_UUID;// { 0x0000111e, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb} };
    DWORD err = BluetoothSetServiceState(&btHeadset, &device, &id, BLUETOOTH_SERVICE_ENABLE);
    if (err == ERROR_SUCCESS)
    {
        std::cout << "Successfully associated with the COM Port" << std::endl;
    }
    else
    {
        std::cout << "Failed to associate with the COM Port" << std::endl;
    }
}

namespace
{
    // {B62C4E8D-62CC-404b-BBBF-BF3E3BBB1374}
    constexpr GUID my_guid = { 0xb62c4e8d, 0x62cc, 0x404b, {0xbb, 0xbf, 0xbf, 0x3e, 0x3b, 0xbb, 0x13, 0x74} };

    constexpr std::size_t CONNECTION_TRANSFER_LEN = 100;

    class bt_socket
    {
    public:
        bt_socket()
        {
            assert(m_socket != INVALID_SOCKET);
        }

        ~bt_socket()
        {
            closesocket(m_socket);
        }

        SOCKET get()
        {
            return m_socket;
        }

    private:
        SOCKET m_socket = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
    };
}

void connect(bt_device_info device)
{
    // data to be transferred
    char data[CONNECTION_TRANSFER_LEN];
    strncpy_s(data, "~!@#$%^&*()-_=+?<>1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", CONNECTION_TRANSFER_LEN - 1);

    printf("\n");

    bt_socket local_socket{};

    // Connect the loacl socket (pSocket) to a given remote socket represented by address
    SOCKADDR_BTH server_socket_address{ AF_BTH, device.info.Address.ullLong, TCP_PROTOCOL_UUID16, 0 };
    if (connect(local_socket.get(), (struct sockaddr*)&server_socket_address, sizeof(SOCKADDR_BTH)) == SOCKET_ERROR)
    {
        throw std::exception{ "connect() call failed." };
        return;
    }

//     if (2 <= g_iOutputLevel)
//     {
//         printf("*INFO* | connect() call succeeded\n");
//     }
// 
//     //
//     // send() call indicates winsock2 to send the given data 
//     // of a specified length over a given connection. 
//     //
//     printf("*INFO* | Sending following data string:\n%s\n", szData);
//     if (SOCKET_ERROR == send(LocalSocket, szData, CXN_TRANSFER_DATA_LENGTH, 0))
//     {
//         printf("=CRITICAL= | send() call failed w/socket = [0x%X], szData = [%p], dataLen = [%d]. WSAGetLastError=[%d]\n", LocalSocket, szData, CXN_TRANSFER_DATA_LENGTH, WSAGetLastError());
//         ulRetCode = 1;
//         goto CleanupAndExit;
//     }
// 
//     if (2 <= g_iOutputLevel)
//     {
//         printf("*INFO* | send() call succeeded\n");
//     }
// 
//     //
//     // Close the socket
//     //
//     if (SOCKET_ERROR == closesocket(LocalSocket))
//     {
//         printf("=CRITICAL= | closesocket() call failed w/socket = [0x%X]. WSAGetLastError=[%d]\n", LocalSocket, WSAGetLastError());
//         ulRetCode = 1;
//         goto CleanupAndExit;
//     }
// 
//     LocalSocket = INVALID_SOCKET;
// 
//     if (2 <= g_iOutputLevel)
//     {
//         printf("*INFO* | closesocket() call succeeded");
//     }
// 
// CleanupAndExit:
//     if (INVALID_SOCKET != LocalSocket)
//     {
//         closesocket(LocalSocket);
//         LocalSocket = INVALID_SOCKET;
//     }
// 
//     return ulRetCode;
}

int main()
{
    try
    {
        const auto bt_devices = scan_bt_devices();
        std::for_each(bt_devices.cbegin(), bt_devices.cend(), [](const auto& map_elem) 
        {
            std::cout << "\n" << "[" << map_elem.first << "]\n" <<
                "Device name:    " << CW2A(map_elem.second.info.szName) << "\n" <<
                "Device address: " << std::hex << std::showbase << map_elem.second.info.Address.ullLong << "\n" <<
                "Device class:   " << std::dec << map_elem.second.info.ulClassofDevice << std::endl;
        });

        std::cout << "\nEnter number of device to pair with: ";
        std::string number;
        std::getline(std::cin, number);

//         pair(bt_devices.at(std::stoul(number)));
        connect(bt_devices.at(std::stoul(number)));
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n" <<
            "Error code: " << WSAGetLastError() <<
            std::endl;
    }

    return 0;
}
