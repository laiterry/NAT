struct icmphdr 
{ 
u_int8_t type;                /* 类型 */ 
u_int8_t code;                /* 代码*/ 
u_int16_t checksum;   /*校验和*/
union 
{ 
    struct 
    { 
      u_int16_t id; 
      u_int16_t sequence; 
    } echo;                     /* echo datagram */ 
    u_int32_t   gateway;        /* gateway address */ 
    struct 
    { 
      u_int16_t __unused; 
      u_int16_t mtu; 
    } frag;                     /* path mtu discovery */ 
} un; 
};