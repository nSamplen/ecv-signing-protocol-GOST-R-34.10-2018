from pygost import gost34112012256
from Cryptodome.Util.number import inverse, GCD
from Cryptodome.Random.random import randint
from sympy import invert
import os
#from elliptic_curve import *
from sys import argv
import asnGenerator


# ----------------------------------------------------------------
# Parameters
# Характеристика поля
p = 57896044622894643241131754937450315750132642216230685504884320870273678881443
# Порядок группы
q = 28948022311447321620565877468725157875067316353637126186229732812867492750347

#  Коэффициенты уравнения кривой
a = 1
b = 41431894589448105498289586872587560387979247722721848579560344157562082667257
p_x = 54672615043105947691210796380713598019547553171137275980323095812145568854782
p_y = 42098178416750523198643432544018510845496542305814546233883323764837032783338

d = 64921815105644748118349040703417588965511539353917797572335798592964210429984 

def check_cmth():
    tmp = 4*pow(a,3)+27*pow(b,2)
    if tmp == 0:
        print("---> !!! Parameters aren-t good!")

def sum(x_P, y_P, x_Q, y_Q):
    if (x_P == 0):
        return x_Q, y_Q
    if (x_Q == 0):
        return x_P, y_P

    if (x_P == x_Q and y_P == y_Q):
      
        m = ((3*x_P*x_P + a) * invert(2*y_P,p)) %p
        x_R = (m ** 2 - x_P - x_Q) % p
        x_R = int(x_R)
        y_R = (m*(x_P - x_R)-y_P)%p

        return x_R, y_R

    m = ((y_P-y_Q) * invert(x_P-x_Q,p)) %p
    x_R = (m ** 2 - x_P-x_Q) %p
    x_R = int(x_R)
    y_R = (m*(x_P - x_R) - y_P)%p

    return x_R, y_R

    
    return None

def _mul_points (x_P, y_P, number):

    if number == 0:
        return None, None
    k = number
    k_binary =  [int(i) for i in bin(k)[2:]]
    t = len(k_binary)
    x_Q = 0
    y_Q = 0
    i = 0
    while i<t:
        if (x_Q != 0 or y_Q != 0):
            x_Q, y_Q = sum(x_Q, y_Q, x_Q, y_Q)
        
        if k_binary[i]!=0:
            x_Q, y_Q = sum(x_P, y_P, x_Q, y_Q)

        i = i+1

    return x_Q, y_Q


def _sign_file(filename, x_Q, y_Q):

    print("Signing file...")

    print("d = ", d)

    file = open(filename, 'rb')
    data = file.read()
    file.close()

    print("---> STEP #1: Calculating hash...")
    
    h = gost34112012256.new(data).digest()
    print('              hash = ',h)

    print("---> STEP #2: Calculating alpha from hash...")
    alpha = int.from_bytes(h,byteorder="big")
    print("              Calculating e = alpha (mod q) ...")
    e = alpha % q
    if e==0:
        print("              e = 0 ---> e = 1")
        e = 1
    else:
        print("              e != 0")

    r = 0
    s = 0
    while r==0 or s==0:
        print("---> STEP #3: Calculating random k (0 < k < q) ...")
        k = randint(int(0), int(q))

        print("---> STEP #4: Calculating C = kP...")
        x_C, y_C = _mul_points(p_x, p_y,k)

        print("---> STEP #4: Calculating r = C_x (mod q) ...")
        r = x_C % q
        if r!=0:
            print("              r != 0")
            print("---> STEP #5: Calculating s = (r*d + k*e) (mod q) ...")
            s = (r*d + k*e) % q
            if s!=0:
                print("              s != 0")
            else:
                print("              r = 0 ---> choosing new random k")
        else:
            print("              r = 0 ---> choosing new random k")
    print(" ---> Gor r, s:")
    print("      r = ", r)
    print("      s = ", s)

    print(" ---> Creating asn.1 file for sign ... ")
    sign_encoded = asnGenerator.encodeSign(x_Q,y_Q,p,a,b,
                                           p_x,p_y,q,r,s)

    print(" ---> Saving asn.1 file ...")
    file = open(filename + '.sign', 'wb')
    file.write(sign_encoded)
    file.close()


def _check_sign(filePath, signPath):

    print("Checking sign of the file...")

    file = open(filePath, 'rb')
    fileData = file.read()
    file.close()

    file = open(signPath, 'rb')
    signData = file.read()
    file.close()

    print("---> STEP #1: Getting r,s, Q_x, Q_y from asn.1 file...")
    x_q, y_q, r, s = asnGenerator.decodeSign(signData)
    print("r = ", r)
    print("s = ", s)
    print("              Checking if (0 < r < q) & (0 < s < q)...")
    if ((r>0 and r<q) and (s>0 and s<q)):
        print("              r and s are OK")
        print("---> STEP #2: Calculating hash of the file...")
        h = gost34112012256.new(fileData).digest()
        print('              hash = {0}'.format(gost34112012256.new(fileData).hexdigest()))
        print("---> STEP #3: Calculating alpha from hash...")
        alpha = int.from_bytes(h,byteorder="big")
        print("              Calculating e = alpha (mod q) ...")
        e = alpha % q
        if e==0:
            print("              e = 0 ---> e = 1")
            e = 1
        else:
            print("              e != 0")

        print("---> STEP #4: Calculating v = e^(-1) (mod q) ...")
        v = invert(e,q)
        print("              v = ", v)

        print("---> STEP #5: Calculating z1 = s*v (mod q) ...")
        print("              Calculating z2 = (-r*v) (mod q) ...")
        z_1 = (s*v) % q 
        z_2 = (-r*v) % q 

        print("---> STEP #6: Calculating C = z1*P + z2*Q  ...")
        x1, y1 = _mul_points(p_x, p_y, z_1)
        x2, y2 = _mul_points(x_q, y_q, z_2)
        x_C, y_C = sum(x1, y1, x2, y2)

        print("              Calculating R = C_x (mod q) ...")
        R = x_C % q
        print("              R = ", R)

        print("---> STEP #7: Checking if R = r ...")
        if R == r:
            print("              ! R = r !")
            return True
        else:
            print("              ! R != r !")
            return False
    
    return False


def main():
    
    k=int(input("1 - sign file\n2 - check sign\n>>> "))

    if (k==1):
        filePath = str(input("Input path of the file to sign...\n>>> "))
        x_q, y_q = _mul_points(p_x,p_y,d)
        _sign_file(filePath,int(x_q),int(y_q))
    else:
        filePath = str(input("Input path of the file...\n>>> "))
        signPath = str(input("Input path of the sign...\n>>> "))
        if _check_sign(filePath,signPath):
                print('sign ok')
        else:
                print('sign failure')


if __name__ == "__main__":
   main()




