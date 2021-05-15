#ifndef __APB_HANDLER_H__
#define __APB_HANDLER_H__

class apb_handler {
public:
  virtual ~apb_handler() = default;
  virtual int read(int address, int &readData) = 0;
  virtual int write(int address, int writeData) = 0;
};

#endif
