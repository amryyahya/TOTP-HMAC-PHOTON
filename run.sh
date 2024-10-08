#!/bin/bash

keys=(
    "1234567890123456"
    "1234567890123456789012345678901212345678901234567890123456789012"
    "12345678901234567890"
    "12345678901234567890123456789012"
    "123456789012345678901234567890"
    "12345678901234567891"
    "12345678901234567892"
    "12345678901234567893"
    "12345678901234567894"
    "Zak8egA6wKaADP9C"
    "2cigAUfjTSgouynY"
    "RNwEqzDsyWKwndrj8aKQ"
    "VSepJRBaqmALnYVi2zxt"
    "OEGqtEhpZqgXolTvZuer"
    "gbcU0tw56GeE5c5JGDk5"
    "I2isyBoyW7Qbkp46j7bj"
    "Rzj5I8EbB4seZKlfyaos"
    "2XSFYEjIbgXP7Qsm06UC"
    "noOWyB1bKck5jwMcJjYrGgy3ooBGEihm"
    "PPofe3TkOr2KEbWa8UtQvWmajK7CgQsN"
    "1YGLnRMCJu0Tht1TQUukp1RfAbPacqpH"
    "TBHupkMJfpR9WFZw9DPC6mvTEiBuzDcD"
    "BrvI5gpNsfXnwBnikRgYrL2r3ZvLmErJ"
    "kxBVKUT0P9a7Hi4bp9jKluTRnbk8I7AF"
    "Tl04UN5syLJjXJFx3mVP1YecPwq9p1G6"
    "wIp3GGMBV42slHxHfdFG5dbRD2gyVZTJ"
    "bSgLPFHYvndHn03s4RGnvjVGXT8RckOq"
    "0Fxaq4G0SxWRiFEYvTH05oeTqm9iu4tM"
    "Xz3yK6rPa5J2W7uCTqMd08BbG1FvLHpNlRDeUZo4kSj9nQVtwIxAsmEgOhYcf"
    "jG4Qh5Kc8tL0d2eVwJ3aB6nXm9zRfUAy1MNbZqPWvCFp7kHToYEiSOsrugxDlI"
    "hJ2x9TqWnF5U4fGzVd8kRmL7aYw1bN3XyP6sQ0CjKHpZMvuBoAeIDSlrcEtOg"
)

times=(
    0 20000000000 59 1111111109 1111111111 
    1234567890 2000000000 20000000000 193247781 
    1623540789 873510432 457620193 1102835657 
    2630451235 3312289764 2157894532 1716119771 
    1012134477 421531042 1568992845 230511997 
    1384690526 765432188 1245789044 3187456109 
    2901348827 1789432710 2987451204 2278904512 
    3367891023 1812345678
)

for i in "${!keys[@]}"; do
    key="${keys[$i]}"
    time="${times[$i]}"
    echo "Input: $key $time"
    echo -e "$key\n$time" | ./main
    echo
done
