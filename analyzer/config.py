PLOTLY_THEME = dict(
    paper_bgcolor="#161b22", plot_bgcolor="#0d1117",
    font=dict(family="IBM Plex Mono", color="#c9d1d9", size=11),
    colorway=["#58a6ff","#3fb950","#d2a8ff","#f0a04b","#ff7b72","#79c0ff","#56d364","#ffa657"],
    xaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
    yaxis=dict(gridcolor="#21262d", linecolor="#30363d"),
)

SEND_TYPES  = ["send", "sendto", "sendmsg", "sendmmsg", "write", "writev", "sendfile"]
RECV_TYPES  = ["recv", "recvfrom", "recvmsg", "recvmmsg", "read", "readv"]
ASYNC_TYPES = ["poll", "ppoll", "select", "pselect", "epoll_wait", "epoll_pwait", "epoll_ctl", "epoll_create"]
CTRL_TYPES  = ["ioctl", "fcntl", "setsockopt", "getsockopt"]