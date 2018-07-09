#include "sysinclude.h"
#include<queue>
using namespace std;
extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

// Suggested in the handbook of NetRiver
typedef enum {data,ack,nak} frame_kind;
typedef struct frame_head
{
	frame_kind kind;
	unsigned int seq;
	unsigned int ack;
	unsigned char data[100];
};
typedef struct frame
{
	frame_head head;
	unsigned int size;
};

// Queue and Window
queue<struct frame> sendList;
deque<struct frame> sendWindow;

/*
* Stop-and-Wait Protocol
*/
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType)
{
	static bool send = true;	// A flag to tag if it is available to send
	struct frame f;
	
	switch(messageType)
	{
		// To send a new frame
		case MSG_TYPE_SEND:
			// Push the frame into the queue
			memcpy(&f,pBuffer,sizeof(f));
			f.size = bufferSize;
			sendList.push(f);
			// If it is available to send
			if(send)
			{
				// Send the first frame in the queue.
				// (There is at least one frame in the queue.)
				f=sendList.front();
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				// Because of the Stop&Wait protocol, after sending one frame,
				// the sender cannot send any new frames, until it receives an ACK.
				send = false;
			}
			break;
		// To receive an ACK
		case MSG_TYPE_RECEIVE:
			// The first frame is received. Pop it.
			sendList.pop();
			// Sending is available.
			send = true;
			// If there are still frames in the queue, continue to send.
			if(!sendList.empty())
			{
				f=sendList.front();
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				send = false;
			}
			break;
		// To handle a timeout exception
		case MSG_TYPE_TIMEOUT:
			// Send the first frame in the queue again.
			f = sendList.front();
			SendFRAMEPacket((unsigned char*)(&f),f.size);
			send = false;
			break;
		// Shouldn't come to default!
		default:
			break;
	}

	return 0;
}

/*
* Back-N Protocol
*/
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
	// Because in BackN protocol the sender sends all frames left
	// in the window, the send flag is not necessary anymore.
	struct frame f;

	switch(messageType)
	{
		// To send a new frame
		case MSG_TYPE_SEND:
			// Push the frame into the queue.
			memcpy(&f,pBuffer,sizeof(f));
			f.size = bufferSize;	
			sendList.push(f);
			// If there are still spare places in the window, 
			// send this frame and push it into the window.
			if(sendWindow.size() < WINDOW_SIZE_BACK_N_FRAME)
			{
				f = sendList.front();
				sendWindow.push_back(f);
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				// The frame waits for its ACK in the window.
				sendList.pop();
			}
			break;
		// To receive an ACK
		case MSG_TYPE_RECEIVE:
			memcpy(&f,pBuffer,sizeof(f));
			// Pop all frames in the window, whose number is
			// lower than or equal to the ACK.
			while(!sendWindow.empty() && ntohl(sendWindow.begin()->head.seq) != ntohl(f.head.ack))
				// Big endien - Small endien
				sendWindow.pop_front();
			if (!sendWindow.empty())
				sendWindow.pop_front();
			// Fill the window with frames in the waiting list,
			// and send all these frames
			while(sendWindow.size()<WINDOW_SIZE_BACK_N_FRAME && !sendList.empty())
			{
				f=sendList.front();
				sendWindow.push_back(f);
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				sendList.pop();
			}
			break;
		// To handle a timeout exception
		case MSG_TYPE_TIMEOUT:
			// Resend all frames
			for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++iter)
				SendFRAMEPacket((unsigned char*)&(*iter),iter->size);
			break;
		// Shouldn't come to default!
		default:
			break;
	}

	return 0;
}

/*
* Selective Repeat
*/
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
	struct frame f;

	switch(messageType)
	{
		// To send a frame
		case MSG_TYPE_SEND:
			// Push the frame into the queue.
			memcpy(&f,pBuffer,sizeof(f));
			f.size=bufferSize;
			sendList.push(f);
			// If there are still spare places in the window, 
			// send this frame and push it into the window.
			if(sendWindow.size() < WINDOW_SIZE_BACK_N_FRAME)
			{
				f=sendList.front();
				sendWindow.push_back(f);
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				sendList.pop();
			}
			break;
		// To receive an ACK/NACK
		case MSG_TYPE_RECEIVE:
			memcpy(&f,pBuffer,sizeof(f));
			// If it is an ACK...
			if(ntohl(f.head.kind) == ack)
			{
				// Pop all frames in the window, whose number is
				// lower than or equal to the ACK.
				while(!sendWindow.empty() && ntohl(sendWindow.begin()->head.seq) != ntohl(f.head.ack))
					// Big endien - Small endien
					sendWindow.pop_front();
				if (!sendWindow.empty())
					sendWindow.pop_front();
			}
			// Otherwise, it is an NACK
			else if(ntohl(f.head.kind) == nak)
				// Find the wrong frame
				for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++iter)
					if(ntohl(f.head.ack)==ntohl(iter->head.seq))
					{
						SendFRAMEPacket((unsigned char*)&(*iter),iter->size);
						break;
					}
			// Fill the window with frames in the waiting list,
			// and send all these frames.
			while(sendWindow.size()<WINDOW_SIZE_BACK_N_FRAME && !sendList.empty())
			{
					f=sendList.front();
					sendWindow.push_back(f);
					sendList.pop();
					SendFRAMEPacket((unsigned char*)(&f),f.size);
			}
			break;
		// To handle a timeout exception
		case MSG_TYPE_TIMEOUT:
			// Wrong frame sequence number
			unsigned int seq;
			memcpy(&seq,pBuffer,sizeof(seq));
			// Find the wrong frame and resend it.
			for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++iter)
				if(ntohl(seq) == ntohl(iter->head.seq))
				{
					SendFRAMEPacket((unsigned char*)(&(*iter)),iter->size);
					break;
				}
			break;
		// Shouldn't come to default!
		default:
			break;
	}

	return 0;
}