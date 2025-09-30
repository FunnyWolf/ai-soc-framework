import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_DATA_DIR = os.path.join(BASE_DIR, 'MODULES_DATA')
REDIS_CONSUMER_GROUP = 'AI_SOC_FRAMEWORK_GROUP'
REDIS_CONSUMER_NAME = 'AI_SOC_FRAMEWORK_CONSUMER_0'

CODE_MSG_ZH = {
    200: '服务器成功返回请求的数据',
    201: '新建或修改数据成功',
    202: '一个请求已经进入后台排队（异步任务）',
    204: '删除数据成功',
    400: '发出的请求有错误，服务器没有进行新建或修改数据的操作',
    401: '用户没有权限（令牌、用户名、密码错误）',
    403: '用户得到授权，但是访问是被禁止的',
    404: '发出的请求针对的是不存在的记录，服务器没有进行操作',
    405: '发送的新建请求失败,返回空数据',
    406: '请求的格式不可得',
    409: '请求的资源存在异常',
    410: '请求的资源被永久删除，且不会再得到的',
    422: '当创建一个对象时，发生一个验证错误',
    500: '服务器发生错误，请检查服务器',
    502: '网关错误',
    503: '服务不可用，服务器暂时过载或维护',
    504: '网关超时',

    # 自定义的错误码
    505: "MSFRPC调用失败",
}

CODE_MSG_EN = {
    200: "The server successfully returned the requested data. ",
    201: "New or modified data succeeded. ",
    202: "A request has entered the background queue (asynchronous task). ",
    204: "Data deleted successfully. ",
    400: "There was an error in the request. The server did not create or modify the data. ",
    401: "The user does not have permission (wrong token, user name, password). ",
    403: "The user is authorized, but access is forbidden. ",
    404: "The request is for a non-existent record, and the server has not operated. ",
    405: "The request method is not allowed. ",
    406: "The format of the request is not available. ",
    410: "The requested resource has been permanently deleted and will no longer be available. ",
    422: "A validation error occurred while creating an object. ",
    500: "An error occurred on the server, please check the server. ",
    502: "Gateway error. ",
    503: "The service is not available. The server is temporarily overloaded or maintained. ",
    504: "Gateway timed out. ",

    # 自定义的错误码
    505: "MSFRPC call failed",
}

BASEAUTH_MSG_ZH = {
    201: '登录成功',

    301: '登录失败,密码错误',
    302: '配置错误,VIPER不允许使用diypassword作为密码!',
    303: 'Viper被暴力破解,请修改密码后登录',
}
BASEAUTH_MSG_EN = {
    201: 'Login successful',

    301: 'Login failed,password error',
    302: 'Configuration error, VIPER does not allow diypassword as a password!',
    303: 'Viper has been brute force attack,please change password',
}

Playbook_MSG_ZH = {
    201: "新建后台任务成功",

    301: "模块前序检查失败,检查函数内部错误",
    305: "获取模块配置失败",
    306: "新建后台任务失败",
    307: "新建后台任务失败",

}

Playbook_MSG_EN = {
    201: "Create background task succeeded",

    301: "Module pre-check failed, check function internal error",
    305: "Failed to get module configuration",
    306: "Failed to create a new background task",
    307: "Failed to create background job",

}

Empty_MSG = {
    201: "",
    202: "",
    203: "",
    204: "",
    205: "",
    206: "",

    301: "",
    302: "",
    303: "",
    304: "",
    305: "",
    306: "",
}

# token超时时间
EXPIRE_MINUTES = 24 * 60

# 静态文件目录
STATIC_STORE_PATH = "STATICFILES/STATIC/"

# lang
CN = "zh-CN"
EN = "en-US"
