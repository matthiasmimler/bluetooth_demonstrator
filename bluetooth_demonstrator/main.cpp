#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2bth.h>
#include <BluetoothAPIs.h>
#include <atlstr.h>

using BT_ADDR = unsigned long long;

struct bt_device_info
{
    std::uint16_t get_nap()
    {
        return GET_NAP(bt_address);
    }

    std::uint32_t get_sap()
    {
        return GET_SAP(bt_address);
    }

    std::uint64_t bt_address{ 0 };
    std::string bt_device_name;
    std::uint32_t bt_namespace{ 0 };
    std::uint32_t bt_device_class{ 0 };
};

union
{
    CHAR buf[5000];
    SOCKADDR_BTH _Unused_; // ensure proper alignment
} butuh;

// bt_device_info query_bt_device_info(std::uint64_t address)
// {
//     int iResult = 0, iRet;
//     BLOB blob;
//     SOCKADDR_BTH sa;
//     CSADDR_INFO csai;
//     WSAQUERYSET wsaq1;
//     HANDLE hLookup1;
//     CHAR buf1[5000];
//     DWORD dwSize;
//     LPWSAQUERYSET pwsaResults1;
//     BTHNS_RESTRICTIONBLOB RBlob;
// 
//     // Initializes the COM library for use by the calling thread
//     if (CoInitializeEx(0, COINIT_MULTITHREADED) != S_OK)
//     {
//         throw std::exception("Something wrong with CoInitializeEx()!");
//     }
// 
//     // http://msdn.microsoft.com/en-us/library/ms881237.aspx
//     // This structure contains details about a query restriction
//     memset(&RBlob, 0, sizeof(RBlob));
//     RBlob.type = SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST;
//     RBlob.numRange = 1;
//     RBlob.pRange[0].minAttribute = SDP_ATTRIB_PROTOCOL_DESCRIPTOR_LIST;
//     RBlob.pRange[0].maxAttribute = SDP_ATTRIB_PROTOCOL_DESCRIPTOR_LIST;
//     RBlob.uuids[0].uuidType = SDP_ST_UUID16;
//     RBlob.uuids[0].u.uuid16 = SerialPortServiceClassID_UUID16;
// 
//     // BrowseGroupDescriptorServiceClassID_UUID;
//     // This structure is used for an arbitrary array of bytes
//     blob.cbSize = sizeof(RBlob);
//     blob.pBlobData = (BYTE*)&RBlob;
// 
//     //This structure defines the Bluetooth socket address
//     memset(&sa, 0, sizeof(sa));
//     sa.btAddr = address;
//     sa.addressFamily = AF_BTH;
// 
//     memset(&csai, 0, sizeof(csai));
//     csai.RemoteAddr.lpSockaddr = (SOCKADDR*)&sa;
//     csai.RemoteAddr.iSockaddrLength = sizeof(sa);
// 
//     memset(&wsaq1, 0, sizeof(wsaq1));
//     wsaq1.dwSize = sizeof(wsaq1);
// 
//     // NS_BTH - The Bluetooth namespace. However this 'bastard' namespace identifier
//     // is supported on Windows Vista and later. Can also try NS_NLA
//     // Using NS_BTH failed with 10022 though with #define _WIN32_WINNT 0x0600
//     wsaq1.dwNameSpace = NS_ALL;
//     wsaq1.lpBlob = &blob;
//     wsaq1.lpcsaBuffer = &csai;
// 
//     auto result = WSALookupServiceBegin(&wsaq1, 0, &hLookup1);
// 
//     if (result != ERROR_SUCCESS)
//     {
//         throw std::exception("query_bt_device_info(): WSALookupServiceBegin() failed");
//     }
// 
//     pwsaResults1 = (LPWSAQUERYSET)buf1;
//     dwSize = sizeof(buf1);
//     memset(pwsaResults1, 0, sizeof(WSAQUERYSET));
//     pwsaResults1->dwSize = sizeof(WSAQUERYSET);
// 
//     // But this part using NS_BTH is OK! Retard lor! %@%#&^%(^@^@^$($&$%
// 
//     pwsaResults1->dwNameSpace = NS_BTH;
//     pwsaResults1->lpBlob = NULL;
// 
//     result = WSALookupServiceNext(hLookup1, 0, &dwSize, pwsaResults1);
// 
//     if (result != ERROR_SUCCESS)
//     {
//         throw std::exception("query_bt_device_info(): WSALookupServiceNext() failed");
//     }
// 
//     printf("BtServiceSearch(): WSALookupServiceNext() is OK!\n");
//     printf("\n(The SDP result processing routine should be called...)\n\n");
// 
//     if (WSALookupServiceEnd(hLookup1) == 0)
//     {
//         printf("BtServiceSearch(): WSALookupServiceEnd(hLookup1) is OK!\n");
//     }
//     else
//     {
//         printf("BtServiceSearch(): WSALookupServiceEnd(hLookup1) failed with error code %ld\n", WSAGetLastError());
//     }
// 
//     // Closes the COM library on the current thread, unloads all DLLs loaded by the thread,
//     // frees any other resources that the thread maintains, and forces all RPC connections
//     // on the thread to close.
//     CoUninitialize();
// 
//     return bt_device_info{};
// }

std::vector<bt_device_info> scan_bt_devices_via_winsock()
{
    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != ERROR_SUCCESS)
    {
        throw std::exception{ "WSAStartup() failed" };
    }

    LPWSAQUERYSET pwsaResults;
    pwsaResults = (LPWSAQUERYSET)butuh.buf;

    WSAQUERYSET wsaq;
    ZeroMemory(&wsaq, sizeof(wsaq));
    wsaq.dwSize = sizeof(wsaq);
    wsaq.dwNameSpace = NS_BTH;
    wsaq.lpcsaBuffer = NULL;

    HANDLE lookup_handle;
    if (WSALookupServiceBegin(&wsaq, LUP_CONTAINERS, &lookup_handle) == SOCKET_ERROR)
    {
        throw std::exception{ "Lookup failed" };
    }

    ZeroMemory(pwsaResults, sizeof(WSAQUERYSET));
    pwsaResults->dwSize = sizeof(WSAQUERYSET);
    pwsaResults->dwNameSpace = NS_BTH;
    pwsaResults->lpBlob = NULL;

    std::vector<bt_device_info> devices;
    DWORD dwSize = sizeof(butuh.buf);
    while (WSALookupServiceNext(lookup_handle, LUP_RETURN_NAME | LUP_RETURN_ADDR, &dwSize, pwsaResults) == 0)
    {
        auto info = bt_device_info{};
        info.bt_address = ((SOCKADDR_BTH*)pwsaResults->lpcsaBuffer->RemoteAddr.lpSockaddr)->btAddr;
        info.bt_device_name = CW2A(pwsaResults->lpszServiceInstanceName);
        info.bt_namespace = pwsaResults->dwNameSpace;
//         auto info = query_bt_device_info(bt_address);

        // get bt remote address

        devices.emplace_back(info);
    }

    if (WSALookupServiceEnd(lookup_handle) != ERROR_SUCCESS)
    {
        throw std::exception{ "FindingBtDevices(): WSALookupServiceEnd(hLookup) failed" };
    }

    if (WSACleanup() != ERROR_SUCCESS)
    {
        throw std::exception{ "WSACleanup() failed" };
    }

    return devices;
}

std::vector<bt_device_info> scan_bt_devices_via_bluetoothapis()
{
    BLUETOOTH_DEVICE_SEARCH_PARAMS search_params =
    {
        sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS), // dwSize (size)
        FALSE, // fReturnAuthenticated (return authenticated devices)
        FALSE, // fReturnRemembered (return remembered devices)
        TRUE, // fReturnUnknown (return unknown devices)
        TRUE, // fReturnConnected (return connected devices)
        TRUE, // fIssueInquiry (issue new inquiry)
        3, // cTimeoutMultiplier (number of increments of 1.28 sec, maximum value is 48)
        NULL // 
    };

    BLUETOOTH_DEVICE_INFO_STRUCT device_info;
    device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO_STRUCT);

    auto devices = std::vector<bt_device_info>{};
    auto find_handle =  BluetoothFindFirstDevice(&search_params, &device_info);

    if (find_handle)
    {
        do
        {
            auto info = bt_device_info{};
            info.bt_device_name = CW2A(device_info.szName);
            info.bt_address = device_info.Address.ullLong;
            info.bt_device_class = device_info.ulClassofDevice;

            devices.emplace_back(info);
        } while (BluetoothFindNextDevice(find_handle, &device_info));
    }

    if (!BluetoothFindDeviceClose(find_handle))
    {
        throw std::exception{ "BluetoothFindDeviceClose() failed" };
    }

    return devices;
}

std::vector<bt_device_info> scan_bt_devices_via_bluetoothapis_and_radio()
{
    BLUETOOTH_FIND_RADIO_PARAMS radio_search_params =
    {
        sizeof(BLUETOOTH_FIND_RADIO_PARAMS)
    };

    HANDLE radio_handle;
    auto radio_result = BluetoothFindFirstRadio(&radio_search_params, &radio_handle);
    if (!radio_result)
    {
        throw std::exception{ "BluetoothFindFirstRadio failed" };
    }

    auto devices = std::vector<bt_device_info>{};
    
    do
    {
        BLUETOOTH_DEVICE_SEARCH_PARAMS search_params =
        {
            sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS), // dwSize (size)
            FALSE, // fReturnAuthenticated (return authenticated devices)
            FALSE, // fReturnRemembered (return remembered devices)
            TRUE, // fReturnUnknown (return unknown devices)
            TRUE, // fReturnConnected (return connected devices)
            TRUE, // fIssueInquiry (issue new inquiry)
            3, // cTimeoutMultiplier (number of increments of 1.28 sec, maximum value is 48)
            radio_handle // 
        };

        BLUETOOTH_DEVICE_INFO_STRUCT device_info;
        device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO_STRUCT);

        auto find_handle = BluetoothFindFirstDevice(&search_params, &device_info);

        if (find_handle)
        {
            do
            {
                auto info = bt_device_info{};
                info.bt_device_name = CW2A(device_info.szName);
                info.bt_address = device_info.Address.ullLong;
                info.bt_device_class = device_info.ulClassofDevice;

                devices.emplace_back(info);
            } while (BluetoothFindNextDevice(find_handle, &device_info));
        }

        if (!BluetoothFindDeviceClose(find_handle))
        {
            throw std::exception{ "BluetoothFindDeviceClose() failed" };
        }

    } while (BluetoothFindNextRadio(radio_result, &radio_handle));

    if (!BluetoothFindRadioClose(radio_result))
    {
        throw std::exception{ "BluetoothFindRadioClose failed" };
    }

    return devices;
}

int main()
{
    try
    {
//         const auto bt_devices = scan_bt_devices_via_winsock();
        const auto bt_devices = scan_bt_devices_via_bluetoothapis();
//         const auto bt_devices = scan_bt_devices_via_bluetoothapis_and_radio();
        std::for_each(bt_devices.cbegin(), bt_devices.cend(), [](const auto& device_info) 
        {
            std::cout << "\n" <<
                "Device name:    " << device_info.bt_device_name << "\n" <<
                "Device address: " << std::hex << std::showbase << device_info.bt_address << "\n" <<
                "Device class:   " << std::dec << device_info.bt_device_class << std::endl;
        });
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n" <<
            "Error code: " << WSAGetLastError() <<
            std::endl;
    }

    return 0;
}
