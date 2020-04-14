// native_processlist.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "native_processlist.h"

int main()
{
	DWORD BufferSize = 0;
	NTSTATUS Status = 0;
	SYSTEM_PROCESS_INFORMATION *RetrievalBuffer;

	Status = NtQuerySystemInformation(
		SystemProcessInformation,
		NULL,
		0,
		&BufferSize);

	if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		RetrievalBuffer =(SYSTEM_PROCESS_INFORMATION *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize);
		if (RetrievalBuffer == NULL)
		{
			return -1;
		}

		Status = NtQuerySystemInformation(
			SystemProcessInformation,
			(PVOID)RetrievalBuffer,
			BufferSize,
			&BufferSize);
		if (!NT_SUCCESS(Status))
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
	while(TRUE)
	{
		LPWSTR ImageName = 0;
		HANDLE Pid = 0,HandleProc = 0,HandleToken = 0;
		ULONG SessionId = 0;
		OBJECT_ATTRIBUTES ProcObjAttr;
		CLIENT_ID TargetPid = {0};
		NTSTATUS Status = 0;

		ImageName = RetrievalBuffer->ImageName.Buffer;
		Pid = RetrievalBuffer->UniqueProcessId;
		SessionId = RetrievalBuffer->SessionId;
		printf("\nProcess name:%ws\nProcess ID:%llx\nSeesion ID:%d\n", ImageName, (ULONG64)Pid, SessionId);
		
		TargetPid.UniqueProcess = Pid;
		InitializeObjectAttributes(&ProcObjAttr, NULL, 0, NULL, 0);
		Status = NtOpenProcess(
			&HandleProc,
			MAXIMUM_ALLOWED,
			&ProcObjAttr,
			&TargetPid);
		if (NT_SUCCESS(Status))
		{
			DWORD RequireSize = 0;
			PTOKEN_PRIVILEGES RetrievalBuffer = 0;
			Status = NtOpenProcessToken(HandleProc, MAXIMUM_ALLOWED, &HandleToken);
			NtQueryInformationToken(
				HandleToken,
				TokenPrivileges,
				NULL,
				0,
				&RequireSize);
			RetrievalBuffer	= (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RequireSize);
			Status = NtQueryInformationToken(
				HandleToken,
				TokenPrivileges,
				RetrievalBuffer,
				RequireSize,
				&RequireSize);

			if (NT_SUCCESS(Status))
			{
				for (size_t i = 0; i < RetrievalBuffer->PrivilegeCount;i++) 
				{
					LPCSTR PrivilegeNameStr;
					DWORD Attribute = RetrievalBuffer->Privileges[i].Attributes;
					static CHAR AttributeName[200] = "";

					ZeroMemory(AttributeName, 200);
					switch (RetrievalBuffer->Privileges[i].Luid.LowPart)
					{
					case 2:
						PrivilegeNameStr = "SE_CREATE_TOKEN_PRIVILEGE";
						break;
					case 3:
						PrivilegeNameStr = "SE_ASSIGNPRIMARYTOKEN_PRIVILEGE";
						break;
					case 4:
						PrivilegeNameStr = "SE_LOCK_MEMORY_PRIVILEGE";
						break;
					case 5:
						PrivilegeNameStr = "SE_INCREASE_QUOTA_PRIVILEGE";
						break;
					case 6:
						PrivilegeNameStr = "SE_MACHINE_ACCOUNT_PRIVILEGE";
						break;
					case 7:
						PrivilegeNameStr = "SE_TCB_PRIVILEGE";
						break;
					case 8:
						PrivilegeNameStr = "SE_SECURITY_PRIVILEGE";
						break;
					case 9:
						PrivilegeNameStr = "SE_TAKE_OWNERSHIP_PRIVILEGE";
						break;
					case 10:
						PrivilegeNameStr = "SE_LOAD_DRIVER_PRIVILEGE";
						break;
					case 11:
						PrivilegeNameStr = "SE_SYSTEM_PROFILE_PRIVILEGE";
						break;
					case 12:
						PrivilegeNameStr = "SE_SYSTEMTIME_PRIVILEGE";
						break;
					case 13:
						PrivilegeNameStr = "SE_PROF_SINGLE_PROCESS_PRIVILEGE";
						break;
					case 14:
						PrivilegeNameStr = "SE_INC_BASE_PRIORITY_PRIVILEGE";
						break;
					case 15:
						PrivilegeNameStr = "SE_CREATE_PAGEFILE_PRIVILEGE";
						break;
					case 16:
						PrivilegeNameStr = "SE_CREATE_PERMANENT_PRIVILEGE";
						break;
					case 17:
						PrivilegeNameStr = "SE_BACKUP_PRIVILEGE";
						break;
					case 18:
						PrivilegeNameStr = "SE_RESTORE_PRIVILEGE";
						break;
					case 19:
						PrivilegeNameStr = "SE_SHUTDOWN_PRIVILEGE";
						break;
					case 20:
						PrivilegeNameStr = "SE_DEBUG_PRIVILEGE";
						break;
					case 21:
						PrivilegeNameStr = "SE_AUDIT_PRIVILEGE";
						break;
					case 22:
						PrivilegeNameStr = "SE_SYSTEM_ENVIRONMENT_PRIVILEGE";
						break;
					case 23:
						PrivilegeNameStr = "SE_CHANGE_NOTIFY_PRIVILEGE";
						break;
					case 24:
						PrivilegeNameStr = "SE_REMOTE_SHUTDOWN_PRIVILEGE";
						break;
					case 25:
						PrivilegeNameStr = "SE_UNDOCK_PRIVILEGE";
						break;
					case 26:
						PrivilegeNameStr = "SE_SYNC_AGENT_PRIVILEGE";
						break;
					case 27:
						PrivilegeNameStr = "SE_ENABLE_DELEGATION_PRIVILEGE";
						break;
					case 28:
						PrivilegeNameStr = "SE_MANAGE_VOLUME_PRIVILEGE";
						break;
					case 29:
						PrivilegeNameStr = "SE_IMPERSONATE_PRIVILEGE";
						break;
					case 30:
						PrivilegeNameStr = "SE_CREATE_GLOBAL_PRIVILEGE";
						break;
					case 31:
						PrivilegeNameStr = "SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE";
						break;
					case 32:
						PrivilegeNameStr = "SE_RELABEL_PRIVILEGE";
						break;
					case 33:
						PrivilegeNameStr = "SE_INC_WORKING_SET_PRIVILEGE";
						break;
					case 34:
						PrivilegeNameStr = "SE_TIME_ZONE_PRIVILEGE";
						break;
					case 35:
						PrivilegeNameStr = "SE_CREATE_SYMBOLIC_LINK_PRIVILEGE";
						break;
					default:
						PrivilegeNameStr = "Know Privilege";
						break;
					}
					if (Attribute & 0x00000001L)
					{
						sprintf_s(&AttributeName[strlen(AttributeName)], 100,"|SE_PRIVILEGE_ENABLED_BY_DEFAULT");
					}
					if (Attribute & 0x00000002L)
					{
						sprintf_s(&AttributeName[strlen(AttributeName)], 100,"|SE_PRIVILEGE_ENABLED");
					}
					if (Attribute & 0x00000004L)
					{
						sprintf_s(&AttributeName[strlen(AttributeName)], 100,"|SE_PRIVILEGE_REMOVED");
					}
					if (Attribute & 0x80000000L)
					{
						sprintf_s(&AttributeName[strlen(AttributeName)], 100,"|SE_PRIVILEGE_REMOVED");
					}
					if (Attribute & ~SE_PRIVILEGE_VALID_ATTRIBUTES)
					{
						sprintf_s(&AttributeName[strlen(AttributeName)], 100,"|ATTRIBUTES_IS_INVALID");
					}
					printf("PRIVILEGE:%s\nATTRIBUTES:%s\n",PrivilegeNameStr,AttributeName);
				}
				
			}
		}
		
		if (!RetrievalBuffer->NextEntryOffset)
		{
			break;
		}
		RetrievalBuffer = (SYSTEM_PROCESS_INFORMATION*)(RetrievalBuffer->NextEntryOffset+(ULONG64)RetrievalBuffer);
	}

	system("pause");
}

