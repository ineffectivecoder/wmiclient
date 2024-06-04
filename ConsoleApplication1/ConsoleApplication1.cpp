#define _WIN32_DCOM
#include <comdef.h>
#include <iostream>
#include <wbemidl.h>
#include <Windows.h>
using namespace std;

#pragma comment(lib, "wbemuuid.lib")
HRESULT hres;
IWbemLocator* pLoc = 0;
IWbemServices * pSvc = 0;
IEnumWbemClassObject* pEnumerator = NULL;
IWbemClassObject* pclsObj = NULL;
ULONG uReturn = 0;
int coinitializecom() {
	
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		cout << "Failed to initialize library" << hex << hres << endl;
		return hres;
	}
	return 0;

}
int comsecurity(){
	hres = CoInitializeSecurity(
		NULL,							// Security Descriptor
		-1,								// COM Neogiates authentication service
		NULL,							// Authentication Services
		NULL,							// Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,      // Default authentication level for proxies
		RPC_C_IMP_LEVEL_IMPERSONATE,    // Default impersonation level for proxies
		NULL,							// Authentication Info
		EOAC_NONE,						// Additional capabitilies of the client or server
		NULL);                          // Reserved

		if (FAILED(hres))
		{
			cout << "Failed to initialize security" << hex << hres << endl;
			CoUninitialize();
			return hres;
		}
		return 0;
}
int connectWMI(_bstr_t space) {
	
	hres = CoCreateInstance(
		CLSID_WbemLocator,		      // CLSID associated with the data and code that will be used to create the object
		0,							  // If NULL, indicates object is not being created as part of an aggregate
		CLSCTX_INPROC_SERVER,         // Context in which the code that manages the newly created object will run
		IID_IWbemLocator,             // A reference to the identifier used to communicate with the object
		(LPVOID*)&pLoc);              // Address of pointer variable that receives the interface pointer

	// Connect to WMI through a call to ConnectServer
	

	hres = pLoc->ConnectServer(
		_bstr_t(space),		  // Namespace to connect to
		NULL,						  // User Name, NULL = current
		NULL,						  // User Password, NULL = current
		0,							  // Locale
		NULL,						  // Security Flags
		0,							  // Authority
		0,							  // Context Object
		&pSvc);                       // IWBemServices Proxy

	if (FAILED(hres))
	{
		cout << "Could not connect.  Error code = 0x" << hex << hres << endl;
		return hres;
	}

	cout << "[+] Connected to the " << space << " namespace" << endl;
	return 0;
}
int printsafearray(SAFEARRAY* safe) {
	long upper, lower;
	BSTR PropName = NULL;
	SafeArrayGetLBound(safe, 1, &lower);
	SafeArrayGetUBound(safe, 1, &upper);
	for (long i = lower; i <= upper; i++) {
		hres = SafeArrayGetElement(
			safe,
			&i,
			&PropName);
		if (FAILED(hres)) {
			return hres;
		}
			wcout << PropName;
			if (i != upper) {
				cout << ", ";
			}
		SysFreeString(PropName);	
	}
	cout << endl;
	return 0;
}
int output() {
	while (pEnumerator)
	{
		HRESULT hres = pEnumerator->Next(
			WBEM_INFINITE,
			1,
			&pclsObj,
			&uReturn);

		if (0 == uReturn) {
			break;
		}

		VARIANT vtProp; // VARIANT?!
		VariantInit(&vtProp);
		// Get value of the Name property
		SAFEARRAY* names = NULL;
		hres = pclsObj->GetNames(
			NULL,
			WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY,
			NULL,
			&names);
		long upper, lower;
		BSTR PropName = NULL;
		SafeArrayGetLBound(names, 1, &lower);
		SafeArrayGetUBound(names, 1, &upper);

		for (long i = lower; i <= upper; i++) {
			hres = SafeArrayGetElement(
				names,
				&i,
				&PropName);
			if (FAILED(hres)) {
				cout << "Shit went sideways" << endl;
				return 2;
			}
			hres = pclsObj->Get(PropName, 0, &vtProp, 0, 0);
			if (FAILED(hres)) {
				cout << "Shit went sideways" << endl;
				return 2;
			}
				wcout << PropName << ": ";
				switch (vtProp.vt) {
				case 1:
					cout << endl;
					break;
				case 2:
					cout << vtProp.iVal << endl;
					break;
				case 3:
					cout << vtProp.lVal << endl;
					break;
				case 8:
					wcout << vtProp.bstrVal << endl;
					break;
				case 11:
					if (vtProp.boolVal) {
						cout << "True" << endl;
					} else {
						cout << "False" << endl;
					}
					break;
				case 17:
					wcout << vtProp.bVal << endl;
					break;
				case 8200:
					printsafearray(vtProp.parray);
					break;
				default:
					cout << "Unsupported (" << vtProp.vt << ")" << endl;
				}
				VariantClear(&vtProp);
				SysFreeString(PropName);			
		}
		SafeArrayDestroy(names);
		pclsObj->Release();
		wcout << endl;
	}
	return 0;
}
int cleanup(int retvalue) {
	if (pSvc != NULL) pSvc->Release();
	if (pLoc != NULL) pLoc->Release();
	CoUninitialize();
	return retvalue;
}
int wmiQuery(_bstr_t query) {
	// Leverage IWbemServices pointer to make requests of WMI, OOOOH WEEE
	
	hres = pSvc->ExecQuery(
		_bstr_t("WQL"),                                          // Query language to use
		_bstr_t(query),											 // Query
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags to specify behavior
		NULL,													 // NULL or pointer to IWbemContext object
		&pEnumerator);											 // If no error, store count of objects

	if (FAILED(hres)) {
		cout << "WMI query has failed, error code = 0x" << hex << hres << endl;
		return 1;
	}

	// Get the data from the query in the previous step
	return output();
}
int main() {
	if (coinitializecom())  cleanup(1); 
	if (comsecurity()) cleanup(1);
	if (connectWMI("ROOT\\CIMV2")) cleanup(1);
	if (wmiQuery("SELECT * FROM WIN32_OperatingSystem")) {
		return cleanup(1);
	}
	
	if (connectWMI("ROOT\\SecurityCenter2")) cleanup(1);
	if (wmiQuery("SELECT * FROM AntiVirusProduct")) {
		return cleanup(1);
	}
	return cleanup(0);
}

// HOMEWORK
/// Miles wants to see everything left aligned....
// loop through the array to find maximum length of property name, store property name and value and maximum length of property name.