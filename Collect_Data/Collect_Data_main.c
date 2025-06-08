#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>




#include "../Include/Memory_Tool_General_Def.h"
#include "../Include/Memory_Tool_Collect_Data.h"
#include "../Include/Memory_Tool_Basic_Func.h"


/**
 * @brief: Show the User Guide
 * @param[in]: none
 * @param[in]: none
 * @param[out]: none
 * @return: void
 * @note:
 */
STATIC VOID Collect_Data_User_Guide(VOID)
{
    fprintf(stdout, "====================================================================================\n");
    fprintf(stdout, "User Guide:    \n\n");
    fprintf(stdout, "memory_trace_tool --[Option] --[PID]\n\n");

    fprintf(stdout, "[Option]:  \n");
    fprintf(stdout, "--p                 Monitor a Single Process.\n");
    fprintf(stdout, "--help              Show the User Guide.\n");
    fprintf(stdout, "--all               Monitor All Processes.\n");

    fprintf(stdout, "\n");
    fprintf(stdout, "[PID]               Choose Process ID.\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "Note: If you choose to monitor all processes, there is no need to fill in [PID].\n");
    fprintf(stdout, "====================================================================================\n");
    fprintf(stdout, "\n");
    return;
}


/**
 * @brief: Parameter Option Validation
 * @param[in]: IN CONST INT argc
 * @param[in]: IN CONST CHAR *pcOption
 * @param[out]: none
 * @return: Error Code
 * @note:
 */
STATIC INT Collect_Data_Params_Opt_Validation(IN CONST INT argc, IN CONST CHAR *pcOption)
{
    if (NULL == pcOption)
    {
        MEMORY_TRACE_ERROR("pcOption is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    }

    if ((0 == strncmp("--p", pcOption, 3)) && (MEM_TRACE_TOOL_MAX_ARGS_NUM == argc))
    {
        MEMORY_TRACE_INFO("Option is [%s]", pcOption);
        return MEM_TRACE_TOOL_SUCCESS;
    }
    else if ((0 != strncmp("--all", pcOption, 5)) && (MEM_TRACE_TOOL_MIN_ARGS_NUM == argc))
    {
        MEMORY_TRACE_INFO("Option is [%s]", pcOption);
        return MEM_TRACE_TOOL_SUCCESS;
    }
    else
    {
        return MEM_TRACE_TOOL_ERROR;
    }


    return MEM_TRACE_TOOL_SUCCESS;
}

STATIC INT Collect_Data_Check_Pid_Is_Valid(IN CONST CHAR *pcPid, OUT INT *piPid)
{
    INT iTmpPid = -1;
    CHAR acPidDir[MEM_TRACE_TOOL_MAX_PID_DIR_LENGTH];

    if (NULL == pcPid)
    {
        MEMORY_TRACE_ERROR("pcPid is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    }

    if (NULL == piPid)
    {
        MEMORY_TRACE_ERROR("pcPid is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    } 

    /* The default assumption is that no one will randomly enter an invalid PID */
    iTmpPid = atoi(pcPid);

    memset(acPidDir, 0, sizeof(acPidDir));
    (VOID)Basic_Scnprintf(acPidDir, sizeof(acPidDir), "/proc/%d", iTmpPid);

    if (0 == access(acPidDir, F_OK))
    {
        MEMORY_TRACE_INFO("Valid Pid %d", iTmpPid);
        *piPid = iTmpPid;
    }
    else
    {
        MEMORY_TRACE_ERROR("Invalid Pid %d", iTmpPid);
    }


    return MEM_TRACE_TOOL_SUCCESS;
}

/**
 * @brief: Parameter Validation
 * @param[in]: IN CONST INT argc
 * @param[in]: IN CONST CHAR **ppcArgv
 * @param[out]: OUT INT *piPid
 * @return: Error Code
 * @note:
 */
STATIC INT Collect_Data_Params_Validation(IN CONST INT argc, IN CONST CHAR CONST **ppcArgv, OUT INT *piPid)
{
    INT iRet = MEM_TRACE_TOOL_SUCCESS;

    if (NULL == piPid)
    {
        MEMORY_TRACE_ERROR("pcPid is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    }

    /* Show the User Guide */
    if ((2 == argc) && (0 == strncmp("--help", ppcArgv[1], 6)))
    {
        Collect_Data_User_Guide();
        return MEM_TARCE_TOOL_USER_GUIDE_HELP;
    }

    /* Parameter Num Validation */
    if ((argc < MEM_TRACE_TOOL_MIN_ARGS_NUM) || (argc > MEM_TRACE_TOOL_MAX_ARGS_NUM))
    {
        MEMORY_TRACE_ERROR("Invalid Args Num[%d]\n", argc);
        return MEM_TRACE_TOOL_INVALID_PARAMS_NUM;
    }

    /* Parameter Content Validation */
    iRet = Collect_Data_Params_Opt_Validation(argc, ppcArgv[1]);
    if (MEM_TRACE_TOOL_SUCCESS != iRet)
    {
        MEMORY_TRACE_ERROR("Invalid Option Cmd %s Or Num %d", ppcArgv[1], argc);
        return MEM_TRACE_TOOL_INVALID_PARAMS_CONTENT;
    }

    iRet = Collect_Data_Check_Pid_Is_Valid(ppcArgv[2], piPid);
    if (MEM_TRACE_TOOL_SUCCESS != iRet)
    {
        MEMORY_TRACE_ERROR("Invalid Pid %s", ppcArgv[2]);
        return MEM_TRACE_TOOL_INVALID_PARAMS_CONTENT;
    }


    return MEM_TRACE_TOOL_SUCCESS;
}

STATIC INT Collect_Data_Create_Task_Thread(IN INT *piTargetPid, OUT pthread_t *pulThreadId)
{
    INT iRet = MEM_TRACE_TOOL_SUCCESS;
    pthread_attr_t stThreadAttr;

    if (NULL == piTargetPid)
    {
        MEMORY_TRACE_ERROR("piTargetPid is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    }

    if (NULL == pulThreadId)
    {
        MEMORY_TRACE_ERROR("pulThreadId is NULL");
        return MEM_TRACE_TOOL_POINTER_IS_NULL;
    }

    (VOID)pthread_attr_init(&stThreadAttr);
    (VOID)pthread_attr_setdetachstate(&stThreadAttr, PTHREAD_CREATE_DETACHED);

    iRet = pthread_create(pulThreadId, &stThreadAttr, (VOID *)Collect_Data_Monitor, piTargetPid);
    if (MEM_TRACE_TOOL_SUCCESS != iRet)
    {
        MEMORY_TRACE_ERROR("Failed to Create Task Thread %s", strerror(errno));
        return MEM_TRACE_TOOL_CREATE_TASK_FALIED;
    }

    return iRet;
}


/**
 * @brief: Main
 * @param[in]: 
 * @param[in]:
 * @param[out]:
 * @return:
 * @note:
 */
    /*The standard command should be:
    memory_trace_tool --p PID (V1.0.0)
    memory_trace_tool --p ALL (V1.1.0)
*/
int main(INT argc, CHAR *argv[])
{   
    INT iRet = MEM_TRACE_TOOL_SUCCESS;
    pid_t TargetPid = -1;
    pthread_t ulTaskThreadId = -1;

    /* 1.Parameter validation */
    iRet = Collect_Data_Params_Validation(argc, (CONST CHAR **)argv, &TargetPid);
    if ((MEM_TRACE_TOOL_SUCCESS != iRet) && (MEM_TARCE_TOOL_USER_GUIDE_HELP != iRet))
    {
        MEMORY_TRACE_ERROR("You Can Obtain the User Guide by Using --help");
        return MEM_TRACE_TOOL_ERROR;
    }

    /* 2.Cteate Task Thread */
    iRet = Collect_Data_Create_Task_Thread(&TargetPid, &ulTaskThreadId);
    if (MEM_TRACE_TOOL_SUCCESS != iRet)
    {
        return MEM_TRACE_TOOL_ERROR;
    }


    while (1)
    {

        sleep(5);
    }

    return MEM_TRACE_TOOL_SUCCESS;
}